//! RC4, needed only because NTLMSSP key exchange seals the session key with it
//! (NTLMSSP_NEGOTIATE_KEY_EXCH). Like MD4, it is here to speak the protocol,
//! not because it is sound.

const std = @import("std");

pub const Rc4 = struct {
    s: [256]u8,
    i: u8 = 0,
    j: u8 = 0,

    pub fn init(key: []const u8) Rc4 {
        var r: Rc4 = .{ .s = undefined };
        for (&r.s, 0..) |*v, idx| v.* = @intCast(idx);
        var j: u8 = 0;
        for (0..256) |idx| {
            j = j +% r.s[idx] +% key[idx % key.len];
            std.mem.swap(u8, &r.s[idx], &r.s[j]);
        }
        return r;
    }

    /// XORs the keystream over `data` in place. Encrypt and decrypt are the
    /// same operation.
    pub fn apply(r: *Rc4, data: []u8) void {
        for (data) |*byte| {
            r.i +%= 1;
            r.j +%= r.s[r.i];
            std.mem.swap(u8, &r.s[r.i], &r.s[r.j]);
            byte.* ^= r.s[r.s[r.i] +% r.s[r.j]];
        }
    }

    pub fn oneShot(key: []const u8, data: []u8) void {
        var r = Rc4.init(key);
        r.apply(data);
    }
};

const testing = std.testing;

test "the classic RC4 test vectors" {
    var data: [9]u8 = "Plaintext".*;
    Rc4.oneShot("Key", &data);
    try testing.expectEqualSlices(u8, &.{ 0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3 }, &data);

    var two: [8]u8 = "pedia".* ++ [_]u8{ 0, 0, 0 };
    var wiki = Rc4.init("Wiki");
    wiki.apply(two[0..5]);
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x21, 0xBF, 0x04, 0x20 }, two[0..5]);
}

test "applying the same keystream twice restores the plaintext" {
    var data: [32]u8 = "sixteen byte secret, and more!!!".*;
    const original = data;
    Rc4.oneShot("session key", &data);
    try testing.expect(!std.mem.eql(u8, &original, &data));
    Rc4.oneShot("session key", &data);
    try testing.expectEqualSlices(u8, &original, &data);
}
