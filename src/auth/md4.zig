//! MD4 (RFC 1320). Present for exactly one reason: the NT hash of a password is
//! MD4 of its UTF-16LE encoding, and NTLMv2 is defined on top of that. It is
//! broken as a hash function and must not be used for anything else.

const std = @import("std");

pub const digest_length = 16;
pub const block_length = 64;

pub const Md4 = struct {
    state: [4]u32 = .{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 },
    buf: [block_length]u8 = undefined,
    buf_len: usize = 0,
    total: u64 = 0,

    pub fn init() Md4 {
        return .{};
    }

    pub fn update(d: *Md4, bytes: []const u8) void {
        d.total += bytes.len;
        var rest = bytes;
        if (d.buf_len > 0) {
            const want = @min(block_length - d.buf_len, rest.len);
            @memcpy(d.buf[d.buf_len..][0..want], rest[0..want]);
            d.buf_len += want;
            rest = rest[want..];
            if (d.buf_len < block_length) return;
            d.compress(&d.buf);
            d.buf_len = 0;
        }
        while (rest.len >= block_length) {
            d.compress(rest[0..block_length]);
            rest = rest[block_length..];
        }
        @memcpy(d.buf[0..rest.len], rest);
        d.buf_len = rest.len;
    }

    pub fn final(d: *Md4, out: *[digest_length]u8) void {
        const bits = d.total *% 8;
        d.update(&.{0x80});
        // The length must land in the last 8 bytes of a block; pad with zeroes
        // until it does, wrapping into a second block when it does not fit.
        while (d.buf_len != block_length - 8) {
            d.update(&.{0});
        }
        d.total -= 8; // the length field itself is not part of the message
        var len_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_bytes, bits, .little);
        d.update(&len_bytes);
        for (d.state, 0..) |word, i| {
            std.mem.writeInt(u32, out[i * 4 ..][0..4], word, .little);
        }
    }

    pub fn hash(bytes: []const u8, out: *[digest_length]u8) void {
        var d = Md4.init();
        d.update(bytes);
        d.final(out);
    }

    fn compress(d: *Md4, block: *const [block_length]u8) void {
        var x: [16]u32 = undefined;
        for (&x, 0..) |*word, i| word.* = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);

        var a = d.state[0];
        var b = d.state[1];
        var c = d.state[2];
        var dd = d.state[3];

        const s1 = [_]u5{ 3, 7, 11, 19 };
        inline for (0..4) |i| {
            a = rol(a +% f(b, c, dd) +% x[i * 4 + 0], s1[0]);
            dd = rol(dd +% f(a, b, c) +% x[i * 4 + 1], s1[1]);
            c = rol(c +% f(dd, a, b) +% x[i * 4 + 2], s1[2]);
            b = rol(b +% f(c, dd, a) +% x[i * 4 + 3], s1[3]);
        }

        const s2 = [_]u5{ 3, 5, 9, 13 };
        inline for (0..4) |i| {
            a = rol(a +% g(b, c, dd) +% x[i + 0] +% 0x5a827999, s2[0]);
            dd = rol(dd +% g(a, b, c) +% x[i + 4] +% 0x5a827999, s2[1]);
            c = rol(c +% g(dd, a, b) +% x[i + 8] +% 0x5a827999, s2[2]);
            b = rol(b +% g(c, dd, a) +% x[i + 12] +% 0x5a827999, s2[3]);
        }

        const s3 = [_]u5{ 3, 9, 11, 15 };
        const order = [_]usize{ 0, 2, 1, 3 };
        inline for (order) |i| {
            a = rol(a +% h(b, c, dd) +% x[i + 0] +% 0x6ed9eba1, s3[0]);
            dd = rol(dd +% h(a, b, c) +% x[i + 8] +% 0x6ed9eba1, s3[1]);
            c = rol(c +% h(dd, a, b) +% x[i + 4] +% 0x6ed9eba1, s3[2]);
            b = rol(b +% h(c, dd, a) +% x[i + 12] +% 0x6ed9eba1, s3[3]);
        }

        d.state[0] +%= a;
        d.state[1] +%= b;
        d.state[2] +%= c;
        d.state[3] +%= dd;
    }

    inline fn f(x: u32, y: u32, z: u32) u32 {
        return (x & y) | (~x & z);
    }
    inline fn g(x: u32, y: u32, z: u32) u32 {
        return (x & y) | (x & z) | (y & z);
    }
    inline fn h(x: u32, y: u32, z: u32) u32 {
        return x ^ y ^ z;
    }
    inline fn rol(v: u32, n: u5) u32 {
        return std.math.rotl(u32, v, n);
    }
};

const testing = std.testing;

fn expectDigest(comptime expected_hex: []const u8, message: []const u8) !void {
    var out: [digest_length]u8 = undefined;
    Md4.hash(message, &out);
    var hex: [digest_length * 2]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&out}) catch unreachable;
    try testing.expectEqualStrings(expected_hex, &hex);
}

test "RFC 1320 test vectors" {
    try expectDigest("31d6cfe0d16ae931b73c59d7e0c089c0", "");
    try expectDigest("bde52cb31de33e46245e05fbdbd6fb24", "a");
    try expectDigest("a448017aaf21d8525fc10ae87aa6729d", "abc");
    try expectDigest("d9130a8164549fe818874806e1c7014b", "message digest");
    try expectDigest("d79e1c308aa5bbcdeea8ed63df412da9", "abcdefghijklmnopqrstuvwxyz");
    try expectDigest(
        "043f8582f241db351ce627e153e7f0e4",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    );
    // Two compression blocks: the only vector that proves `update` carries
    // state across a block boundary.
    try expectDigest(
        "e33b4ddc9c38f2199c3e7b164fcc0536",
        "1234567890" ** 8,
    );
}

test "streaming in odd-sized chunks matches a single pass" {
    const message = "the quick brown fox jumps over the lazy dog, twice, at length" ** 4;
    var once: [digest_length]u8 = undefined;
    Md4.hash(message, &once);

    var d = Md4.init();
    var i: usize = 0;
    while (i < message.len) : (i += 7) d.update(message[i..@min(i + 7, message.len)]);
    var streamed: [digest_length]u8 = undefined;
    d.final(&streamed);

    try testing.expectEqualSlices(u8, &once, &streamed);
}
