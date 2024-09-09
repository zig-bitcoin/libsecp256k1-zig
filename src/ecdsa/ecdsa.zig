const std = @import("std");
const secp256k1 = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_recovery.h");
    @cInclude("secp256k1_preallocated.h");
    @cInclude("secp256k1_schnorrsig.h");
});
const secp = @import("../secp256k1.zig");

const serialized_signature = @import("serialized_signature.zig");
const SerializedSignature = @import("serialized_signature.zig").SerializedSignature;

/// An ECDSA signature
pub const Signature = struct {
    inner: secp256k1.secp256k1_ecdsa_signature,

    pub fn fromString(s: []const u8) !Signature {
        if (s.len / 2 > serialized_signature.MAX_LEN) return error.InvalidSignature;
        var res = [_]u8{0} ** serialized_signature.MAX_LEN;

        return try fromDer(try std.fmt.hexToBytes(&res, s));
    }

    pub fn toString(self: Signature) [serialized_signature.MAX_LEN * 2]u8 {
        return self.serializeDer().toString();
    }

    /// Converts a DER-encoded byte slice to a signature
    pub fn fromDer(data: []const u8) !Signature {
        if (data.len == 0) {
            return error.InvalidSignature;
        }

        var ret: secp256k1.secp256k1_ecdsa_signature = .{};
        if (secp256k1.secp256k1_ecdsa_signature_parse_der(
            secp256k1.secp256k1_context_no_precomp,
            &ret,
            data.ptr,
            data.len,
        ) == 1) {
            return .{
                .inner = ret,
            };
        } else {
            return error.InvalidSignature;
        }
    }

    /// Converts a 64-byte compact-encoded byte slice to a signature
    pub fn fromCompact(data: []const u8) !Signature {
        if (data.len != 64) {
            return error.InvalidSignature;
        }
        var ret: secp256k1.secp256k1_ecdsa_signature = .{};

        if (secp256k1.secp256k1_ecdsa_signature_parse_compact(
            secp256k1.secp256k1_context_no_precomp,
            &ret,
            data.ptr,
        ) == 1) {
            return .{ .inner = ret };
        } else {
            return error.InvalidSignature;
        }
    }

    /// Converts a "lax DER"-encoded byte slice to a signature. This is basically
    /// only useful for validating signatures in the Bitcoin blockchain from before
    /// 2016. It should never be used in new applications. This library does not
    /// support serializing to this "format"
    pub fn fromDerLax(data: []const u8) !Signature {
        if (data.len == 0) {
            return error.InvalidSignature;
        }

        var ret: secp256k1.secp256k1_ecdsa_signature = .{};
        if (secp256k1.ecdsa_signature_parse_der_lax(
            secp256k1.secp256k1_context_no_precomp,
            &ret,
            data.ptr,
            data.len,
        ) == 1) {
            return .{ .inner = ret };
        } else {
            return error.InvalidSignature;
        }
    }

    /// Normalizes a signature to a "low S" form. In ECDSA, signatures are
    /// of the form (r, s) where r and s are numbers lying in some finite
    /// field. The verification equation will pass for (r, s) iff it passes
    /// for (r, -s), so it is possible to ``modify'' signatures in transit
    /// by flipping the sign of s. This does not constitute a forgery since
    /// the signed message still cannot be changed, but for some applications,
    /// changing even the signature itself can be a problem. Such applications
    /// require a "strong signature". It is believed that ECDSA is a strong
    /// signature except for this ambiguity in the sign of s, so to accommodate
    /// these applications libsecp256k1 considers signatures for which s is in
    /// the upper half of the field range invalid. This eliminates the
    /// ambiguity.
    ///
    /// However, for some systems, signatures with high s-values are considered
    /// valid. (For example, parsing the historic Bitcoin blockchain requires
    /// this.) For these applications we provide this normalization function,
    /// which ensures that the s value lies in the lower half of its range.
    pub fn normalizeS(self: *Signature) void {

        // Ignore return value, which indicates whether the sig
        // was already normalized. We don't care.
        _ = secp256k1.secp256k1_ecdsa_signature_normalize(
            secp256k1.secp256k1_context_no_precomp,
            &self.inner,
            &self.inner,
        );
    }

    /// Serializes the signature in DER format
    pub fn serializeDer(self: *const Signature) SerializedSignature {
        var data = [_]u8{0} ** serialized_signature.MAX_LEN;

        var len: usize = serialized_signature.MAX_LEN;
        const err = secp256k1.secp256k1_ecdsa_signature_serialize_der(
            secp256k1.secp256k1_context_no_precomp,
            &data,
            &len,
            &self.inner,
        );

        std.debug.assert(err == 1);

        return SerializedSignature.fromRawParts(data, len);
    }

    /// Serializes the signature in compact format
    pub inline fn serializeCompact(self: *const Signature) [64]u8 {
        var ret: [64]u8 = undefined;
        const err = secp256k1.secp256k1_ecdsa_signature_serialize_compact(
            secp256k1.secp256k1_context_no_precomp,
            &ret,
            &self.inner,
        );

        std.debug.assert(err == 1);
        return ret;
    }
};

pub const Secp = struct {
    fn signEcdsaWithNoncedataPointer(
        self: secp.Secp256k1,
        msg: secp.Message,
        sk: secp.SecretKey,
        noncedata: ?[32]u8,
    ) Signature {
        var ret: secp256k1.secp256k1_ecdsa_signature = .{};

        const nonce_ptr: ?*const anyopaque = if (noncedata) |*data| data else null;

        // We can assume the return value because it's not possible to construct
        // an invalid signature from a valid `Message` and `SecretKey`
        std.debug.assert(secp256k1.secp256k1_ecdsa_sign(
            self.ctx,
            &ret,
            &msg.inner,
            &sk.data,
            secp256k1.secp256k1_nonce_function_rfc6979,
            nonce_ptr,
        ) == 1);

        return .{
            .inner = ret,
        };
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
    pub fn signEcdsa(self: secp.Secp256k1, msg: secp.Message, sk: secp.SecretKey) Signature {
        return signEcdsaWithNoncedataPointer(self, msg, sk, null);
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// and includes 32 bytes of noncedata in the nonce generation via inclusion in
    /// one of the hash operations during nonce generation. This is useful when multiple
    /// signatures are needed for the same Message and SecretKey while still using RFC6979.
    /// Requires a signing-capable context.
    pub fn signEcdsaWithNoncedata(
        self: secp.Secp256k1,
        msg: secp.Message,
        sk: secp.SecretKey,
        noncedata: [32]u8,
    ) Signature {
        return signEcdsaWithNoncedataPointer(self, msg, sk, noncedata);
    }

    fn signGrindWithCheck(
        self: secp.Secp256k1,
        msg: secp.Message,
        sk: secp.SecretKey,
        check: *const fn (secp256k1.secp256k1_ecdsa_signature) bool,
    ) Signature {
        var entropy_p: ?*anyopaque = null;
        var counter: u32 = 0;
        var extra_entropy = [_]u8{0} ** 32;
        while (true) {
            var ret: secp256k1.secp256k1_ecdsa_signature = .{};
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            std.debug.assert(
                secp256k1.secp256k1_ecdsa_sign(
                    self.ctx,
                    &ret,
                    &msg.inner,
                    &sk.data,
                    secp256k1.secp256k1_nonce_function_rfc6979,
                    entropy_p,
                ) == 1,
            );

            if (check(ret)) {
                return .{ .inner = ret };
            }

            counter += 1;
            std.mem.writeInt(u32, extra_entropy[0..4], counter, .little);

            entropy_p = &extra_entropy;
        }
    }

    /// Constructs a signature for `msg` using the secret key `sk`, RFC6979 nonce
    /// and "grinds" the nonce by passing extra entropy if necessary to produce
    /// a signature that is less than 71 - `bytes_to_grind` bytes. The number
    /// of signing operation performed by this function is exponential in the
    /// number of bytes grinded.
    /// Requires a signing capable context.
    pub fn signEcdsaGrindR(
        self: secp.Secp256k1,
        msg: secp.Message,
        sk: secp.SecretKey,
        bytes_to_grind: usize,
    ) Signature {
        const len_check = (struct {
            fn check(s: secp256k1.secp256k1_ecdsa_signature) bool {
                return derLengthCheck(s, 71 - bytes_to_grind);
            }
        }).check;

        return signGrindWithCheck(self, msg, sk, &len_check);
    }

    /// Constructs a signature for `msg` using the secret key `sk`, RFC6979 nonce
    /// and "grinds" the nonce by passing extra entropy if necessary to produce
    /// a signature that is less than 71 bytes and compatible with the low r
    /// signature implementation of bitcoin core. In average, this function
    /// will perform two signing operations.
    /// Requires a signing capable context.
    pub fn signEcdsaLowR(
        self: secp.Secp256k1,
        msg: secp.Message,
        sk: secp.SecretKey,
    ) Signature {
        return signGrindWithCheck(self, msg, sk, &compactSigHasZeroFirstBit);
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(())` on success. Note that this function cannot
    /// be used for Bitcoin consensus checking since there may exist signatures
    /// which OpenSSL would verify but not libsecp256k1, or vice-versa. Requires a
    /// verify-capable context.
    /// ```
    pub inline fn verifyEcdsa(
        self: secp.Secp256k1,
        msg: secp.Message,
        sig: Signature,
        pk: secp.PublicKey,
    ) !void {
        if (secp256k1.secp256k1_ecdsa_verify(self.ctx, &sig.inner, &msg.inner, &pk.pk) != 1) {
            return error.InvalidSignature;
        }
    }
};

pub fn compactSigHasZeroFirstBit(sig: secp256k1.secp256k1_ecdsa_signature) bool {
    var compact = [_]u8{0} ** 64;
    const err = secp256k1.secp256k1_ecdsa_signature_serialize_compact(
        secp256k1.secp256k1_context_no_precomp,
        &compact,
        &sig,
    );

    std.debug.assert(err == 1);
    return compact[0] < 0x80;
}

pub fn derLengthCheck(sig: secp256k1.secp256k1_ecdsa_signature, max_len: usize) bool {
    var ser_ret = [_]u8{0} ** 72;
    var len: usize = ser_ret.len;

    const err = secp256k1.secp256k1_ecdsa_signature_serialize_der(
        secp256k1.secp256k1_context_no_precomp,
        &ser_ret,
        &len,
        &sig,
    );
    std.debug.assert(err == 1);
    return len <= max_len;
}
