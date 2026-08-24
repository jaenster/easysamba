//! SMB2 message signing.
//!
//! A signature covers the whole message — header included — with the signature
//! field itself zeroed. Which MAC is used depends on the dialect: HMAC-SHA256
//! for 2.x, AES-128-CMAC over a derived key for 3.x. Only the 2.x path is
//! reachable today (see `smb/negotiate.zig` for why the server stops at 2.1),
//! but the key derivation for 3.x is here because signing is exactly where a
//! dialect bump would otherwise go wrong quietly.
//!
//! Signing matters more than it looks: a Windows 11 client requires it by
//! default and will refuse a server that cannot sign, and an unsigned session
//! is a session an on-path attacker can rewrite.

const std = @import("std");
const header = @import("header.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const CmacAes128 = std.crypto.auth.cmac.CmacAes128;

pub const signature_offset: usize = 48;
pub const signature_len: usize = 16;

pub const Algorithm = enum { hmac_sha256, aes_cmac };

pub fn algorithmFor(dialect: header.Dialect) Algorithm {
    return switch (dialect) {
        .smb_3_0, .smb_3_0_2, .smb_3_1_1 => .aes_cmac,
        else => .hmac_sha256,
    };
}

/// Computes the signature over `message`, which must be a complete SMB2 message
/// starting at its header (no transport prefix).
pub fn compute(algorithm: Algorithm, key: [16]u8, message: []const u8) [signature_len]u8 {
    std.debug.assert(message.len >= header.header_size);
    const head = message[0..signature_offset];
    const zeroed = [_]u8{0} ** signature_len;
    const tail = message[signature_offset + signature_len ..];

    var out: [signature_len]u8 = undefined;
    switch (algorithm) {
        .hmac_sha256 => {
            var mac = HmacSha256.init(&key);
            mac.update(head);
            mac.update(&zeroed);
            mac.update(tail);
            var full: [HmacSha256.mac_length]u8 = undefined;
            mac.final(&full);
            @memcpy(&out, full[0..signature_len]);
        },
        .aes_cmac => {
            var mac = CmacAes128.init(&key);
            mac.update(head);
            mac.update(&zeroed);
            mac.update(tail);
            mac.final(&out);
        },
    }
    return out;
}

/// Signs in place and sets the SIGNED flag.
pub fn sign(algorithm: Algorithm, key: [16]u8, message: []u8) void {
    const current = std.mem.readInt(u32, message[16..20], .little);
    std.mem.writeInt(u32, message[16..20], current | header.flags.SIGNED, .little);
    const mac = compute(algorithm, key, message);
    @memcpy(message[signature_offset..][0..signature_len], &mac);
}

/// Constant-time check of a received message's signature.
pub fn verify(algorithm: Algorithm, key: [16]u8, message: []const u8) bool {
    if (message.len < header.header_size) return false;
    const claimed: [signature_len]u8 = message[signature_offset..][0..signature_len].*;
    const expected = compute(algorithm, key, message);
    return std.crypto.timing_safe.eql([signature_len]u8, claimed, expected);
}

/// SP800-108 counter-mode KDF with HMAC-SHA256, one 128-bit output block —
/// how SMB3 turns a session key into its signing, encryption and application
/// keys. Unused until a 3.x dialect is offered; kept beside the algorithm
/// switch it belongs to.
pub fn kdf(key: [16]u8, label: []const u8, context: []const u8) [16]u8 {
    var mac = HmacSha256.init(&key);
    mac.update(&[_]u8{ 0, 0, 0, 1 }); // i = 1
    mac.update(label);
    mac.update(&[_]u8{0}); // label terminator
    mac.update(context);
    mac.update(&[_]u8{ 0, 0, 0, 128 }); // L = 128 bits
    var full: [HmacSha256.mac_length]u8 = undefined;
    mac.final(&full);
    return full[0..16].*;
}

const testing = std.testing;
const wire = @import("wire.zig");

fn sampleMessage(buf: []u8) []u8 {
    var w = wire.Writer.init(buf);
    header.write(&w, .{
        .command = .tree_connect,
        .credits = 1,
        .message_id = 4,
        .session_id = 0x1234,
        .signature = @splat(0xFF), // whatever was there must not be signed over
    }) catch unreachable;
    w.blob("payload bytes") catch unreachable;
    return w.written();
}

test "sign then verify, and a single flipped byte breaks it" {
    var buf: [128]u8 = undefined;
    const message = sampleMessage(&buf);
    const key: [16]u8 = @splat(0x42);

    sign(.hmac_sha256, key, message);
    try testing.expect(verify(.hmac_sha256, key, message));
    // Signing must have set the flag, or a client would ignore the signature.
    try testing.expect(std.mem.readInt(u32, message[16..20], .little) & header.flags.SIGNED != 0);

    message[70] ^= 0x01;
    try testing.expect(!verify(.hmac_sha256, key, message));
}

test "the signature does not depend on what the field held before" {
    var a_buf: [128]u8 = undefined;
    var b_buf: [128]u8 = undefined;
    const a = sampleMessage(&a_buf);
    const b = sampleMessage(&b_buf);
    @memset(b[signature_offset..][0..signature_len], 0);
    const key: [16]u8 = @splat(7);
    try testing.expectEqualSlices(u8, &compute(.hmac_sha256, key, a), &compute(.hmac_sha256, key, b));
}

test "a different key or algorithm produces a different signature" {
    var buf: [128]u8 = undefined;
    const message = sampleMessage(&buf);
    const a = compute(.hmac_sha256, @splat(1), message);
    const b = compute(.hmac_sha256, @splat(2), message);
    const c = compute(.aes_cmac, @splat(1), message);
    try testing.expect(!std.mem.eql(u8, &a, &b));
    try testing.expect(!std.mem.eql(u8, &a, &c));

    sign(.aes_cmac, @splat(1), message);
    try testing.expect(verify(.aes_cmac, @splat(1), message));
    try testing.expect(!verify(.hmac_sha256, @splat(1), message));
}

test "algorithmFor follows the dialect" {
    try testing.expectEqual(Algorithm.hmac_sha256, algorithmFor(.smb_2_0_2));
    try testing.expectEqual(Algorithm.hmac_sha256, algorithmFor(.smb_2_1));
    try testing.expectEqual(Algorithm.aes_cmac, algorithmFor(.smb_3_1_1));
}

test "the SMB3 KDF separates keys by label" {
    const key: [16]u8 = @splat(9);
    const signing = kdf(key, "SMB2AESCMAC", "SmbSign\x00");
    const application = kdf(key, "SMB2APP", "SmbRpc\x00");
    try testing.expect(!std.mem.eql(u8, &signing, &application));
}
