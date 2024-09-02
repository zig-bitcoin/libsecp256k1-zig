const std = @import("std");
const secp256k1 = @import("secp256k1.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn generateKeypair() !void {
    const secp = try secp256k1.Secp256k1.genNew();
    defer secp.deinit();

    var rng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));

    // First option:
    {
        const seckey, const pubkey = try secp.generateKeypair(rng.random());
        try std.testing.expectEqual(pubkey, secp256k1.PublicKey.fromSecretKey(secp, seckey));
    }
    // Second option:
    {
        const seckey = secp256k1.SecretKey.generateWithRandom(rng.random());
        const pubkey = secp256k1.PublicKey.fromSecretKey(secp, seckey);
        _ = pubkey; // autofix
    }
}

pub fn main() !void {
    // generate key pair example
    try generateKeypair();
}
