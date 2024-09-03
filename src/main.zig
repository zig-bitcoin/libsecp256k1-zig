const std = @import("std");
const secp256k1 = @import("secp256k1");
const Sha256 = std.crypto.hash.sha2.Sha256;
const rand = std.crypto.random;
pub fn generateKeypair() !void {
    const secp = try secp256k1.Secp256k1.genNew();
    defer secp.deinit();

    // First option:
    {
        const seckey, const pubkey = try secp.generateKeypair(rand);
        try std.testing.expectEqual(pubkey, secp256k1.PublicKey.fromSecretKey(secp, seckey));
    }
    // Second option:
    {
        const seckey = secp256k1.SecretKey.generateWithRandom(rand);
        const pubkey = secp256k1.PublicKey.fromSecretKey(secp, seckey);
        _ = pubkey; // autofix
    }
}

pub fn signAndVerifyEcdsa() !void {
    const secp = try secp256k1.Secp256k1.genNew();
    defer secp.deinit();

    const seckey = secp256k1.SecretKey.generateWithRandom(rand);
    const pubkey = secp256k1.PublicKey.fromSecretKey(secp, seckey);

    var buf: [32]u8 = undefined;
    // zig bitcoin
    const messageHash = try std.fmt.hexToBytes(&buf, "D95F5DB92F175E6489219D1B23B3EFBF0D353DED9224DCD4B9AF3F3CB983469B");

    const signature = try secp.signEcdsa(seckey, messageHash[0..32].*);
    try secp.verifyEcdsa(signature, messageHash[0..32].*, pubkey);
}

pub fn main() !void {

    // generate key pair example
    try generateKeypair();

    // ecdsa example
    try signAndVerifyEcdsa();
}
