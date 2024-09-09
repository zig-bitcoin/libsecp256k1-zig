const std = @import("std");
const constants = @import("constants.zig");
const Secp256k1 = @import("secp256k1.zig").Secp256k1;
const KeyPair = @import("secp256k1.zig").KeyPair;
const XOnlyPublicKey = @import("secp256k1.zig").XOnlyPublicKey;

const secp256k1 = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_recovery.h");
    @cInclude("secp256k1_preallocated.h");
    @cInclude("secp256k1_schnorrsig.h");
});

pub const Signature = struct {
    inner: [constants.schnorr_signature_size]u8,

    pub fn fromStr(s: []const u8) !Signature {
        if (s.len > constants.schnorr_signature_size * 2) return error.InvalidSignature;
        var res: [constants.schnorr_signature_size]u8 = undefined;

        _ = try std.fmt.hexToBytes(&res, s);

        return .{ .inner = res };
    }
};

pub const Secp = struct {
    /// Creates a schnorr signature using the given auxiliary random data.
    pub fn signSchnorrWithAuxRand(
        self: *const Secp256k1,
        msg: [32]u8,
        keypair: KeyPair,
        aux_rand: [32]u8,
    ) !Signature {
        return try self.signSchnorrHelper(&msg, keypair, &aux_rand);
    }

    /// Verifies a schnorr signature.
    pub fn verifySchnorr(
        self: *const Secp256k1,
        sig: Signature,
        msg: [32]u8,
        pubkey: XOnlyPublicKey,
    ) !void {
        if (secp256k1.secp256k1_schnorrsig_verify(
            self.ctx,
            &sig.inner,
            &msg,
            32,
            &pubkey.inner,
        ) != 1) return error.InvalidSignature;
    }

    pub fn signSchnorrHelper(self: *const Secp256k1, msg: []const u8, keypair: KeyPair, nonce_data: []const u8) !Signature {
        var sig: [64]u8 = undefined;

        std.debug.assert(1 == secp256k1.secp256k1_schnorrsig_sign(self.ctx, (&sig).ptr, msg.ptr, &keypair.inner, nonce_data.ptr));

        return .{ .inner = sig };
    }
};
