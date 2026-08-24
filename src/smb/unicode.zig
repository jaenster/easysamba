//! UTF-16LE on the wire, UTF-8 everywhere inside. The conversions read and
//! write byte slices rather than []u16 because SMB2 buffers are never
//! guaranteed to be two-byte aligned.
//!
//! Also home to path handling: the one place that turns a client-supplied
//! `dir\sub\file.txt` into a path an adapter may act on. Everything hostile
//! about SMB paths (absolute paths, `..`, NUL, alternate data streams, empty
//! components) is rejected here, once, so no adapter has to remember to.

const std = @import("std");

pub const Error = error{
    /// Output buffer too small for the converted string.
    NoSpace,
    /// Malformed UTF-16 (lone surrogate, odd byte count) or unencodable scalar.
    BadEncoding,
    /// A syntactically valid string that must never reach an adapter:
    /// `..`, a leading separator, an embedded NUL, a stream suffix.
    BadPath,
};

/// The longest path this server will carry, in UTF-8 bytes. Windows' own limit
/// is 32760 UTF-16 units; a fixed 4 KiB covers every real share layout and
/// bounds every buffer that holds a path.
pub const max_path = 4096;
pub const max_name = 512;

/// Decodes UTF-16LE bytes into `out`, returning the UTF-8 slice.
pub fn toUtf8(out: []u8, src: []const u8) Error![]u8 {
    if (src.len % 2 != 0) return error.BadEncoding;
    var w: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        const unit = std.mem.readInt(u16, src[i..][0..2], .little);
        i += 2;
        var cp: u21 = unit;
        if (unit >= 0xD800 and unit < 0xDC00) {
            if (src.len - i < 2) return error.BadEncoding;
            const low = std.mem.readInt(u16, src[i..][0..2], .little);
            if (low < 0xDC00 or low > 0xDFFF) return error.BadEncoding;
            i += 2;
            cp = 0x10000 + ((@as(u21, unit - 0xD800) << 10) | (low - 0xDC00));
        } else if (unit >= 0xDC00 and unit <= 0xDFFF) {
            return error.BadEncoding; // unpaired low surrogate
        }
        const n = std.unicode.utf8CodepointSequenceLength(cp) catch return error.BadEncoding;
        if (out.len - w < n) return error.NoSpace;
        _ = std.unicode.utf8Encode(cp, out[w..]) catch return error.BadEncoding;
        w += n;
    }
    return out[0..w];
}

/// Encodes UTF-8 into UTF-16LE bytes in `out`.
pub fn toUtf16le(out: []u8, src: []const u8) Error![]u8 {
    var w: usize = 0;
    var it = std.unicode.Utf8Iterator{ .bytes = src, .i = 0 };
    while (true) {
        const slice = it.nextCodepointSlice() orelse break;
        const cp = std.unicode.utf8Decode(slice) catch return error.BadEncoding;
        if (cp < 0x10000) {
            if (out.len - w < 2) return error.NoSpace;
            std.mem.writeInt(u16, out[w..][0..2], @intCast(cp), .little);
            w += 2;
        } else {
            if (out.len - w < 4) return error.NoSpace;
            const v = cp - 0x10000;
            std.mem.writeInt(u16, out[w..][0..2], @intCast(0xD800 + (v >> 10)), .little);
            std.mem.writeInt(u16, out[w + 2 ..][0..2], @intCast(0xDC00 + (v & 0x3FF)), .little);
            w += 4;
        }
    }
    return out[0..w];
}

/// UTF-16LE byte length of a UTF-8 string, without converting it.
pub fn utf16leLen(src: []const u8) Error!usize {
    var n: usize = 0;
    var it = std.unicode.Utf8Iterator{ .bytes = src, .i = 0 };
    while (it.nextCodepointSlice()) |slice| {
        const cp = std.unicode.utf8Decode(slice) catch return error.BadEncoding;
        n += if (cp < 0x10000) @as(usize, 2) else 4;
    }
    return n;
}

/// Rewrites a client path into the adapter form: UTF-8, `/`-separated, no
/// leading or trailing separator, no empty components. The share root is the
/// empty string.
///
/// Rejected outright: `..` in any component, an embedded NUL, a `:` stream
/// suffix (`file.txt:stream:$DATA` would otherwise reach the filesystem as a
/// real name on hosts where `:` is legal), and anything longer than max_path.
/// A leading `\` is tolerated and stripped — clients disagree about sending it.
pub fn normalizePath(out: []u8, wire: []const u8) Error![]u8 {
    if (wire.len > max_path) return error.BadPath;
    var w: usize = 0;
    var component_start: usize = 0;
    var i: usize = 0;
    while (i <= wire.len) : (i += 1) {
        const at_end = i == wire.len;
        const ch: u8 = if (at_end) '\\' else wire[i];
        if (ch != '\\' and ch != '/') {
            if (ch == 0 or ch == ':') return error.BadPath;
            continue;
        }
        const component = wire[component_start..i];
        component_start = i + 1;
        if (component.len == 0) continue; // `a\\b`, a leading `\`, a trailing `\`
        if (std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) return error.BadPath;
        // Windows silently strips trailing dots and spaces; a client that sends
        // `foo.` means `foo`, and a name that is nothing but dots is malformed.
        var trimmed = component;
        while (trimmed.len > 0 and (trimmed[trimmed.len - 1] == '.' or trimmed[trimmed.len - 1] == ' ')) {
            trimmed.len -= 1;
        }
        if (trimmed.len == 0) return error.BadPath;
        if (w > 0) {
            if (out.len - w < 1) return error.NoSpace;
            out[w] = '/';
            w += 1;
        }
        if (out.len - w < trimmed.len) return error.NoSpace;
        @memcpy(out[w..][0..trimmed.len], trimmed);
        w += trimmed.len;
    }
    return out[0..w];
}

/// The last component of a normalized path, or "" for the root.
pub fn baseName(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| return path[i + 1 ..];
    return path;
}

/// Everything before the last component, or "" when the path is a single name.
pub fn dirName(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| return path[0..i];
    return path[0..0];
}

/// ASCII-case-insensitive equality. SMB is case-insensitive but case-
/// preserving; folding beyond ASCII would need the full Unicode upcase table
/// Windows uses, so non-ASCII bytes compare exactly — the conservative half of
/// the trade, where the only cost is that `Ä` and `ä` look like two names.
pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

/// DOS-style wildcard match used by QUERY_DIRECTORY search patterns.
/// `*` matches any run, `?` matches one character. The three DOS quoting
/// characters clients still emit are folded onto their modern equivalents:
/// `<` (DOS_STAR) → `*`, `>` (DOS_QM) → `?`, `"` (DOS_DOT) → `.`.
pub fn matchWildcard(pattern: []const u8, name: []const u8) bool {
    var p: usize = 0;
    var n: usize = 0;
    var star_p: ?usize = null;
    var star_n: usize = 0;
    while (n < name.len) {
        const pc: ?u8 = if (p < pattern.len) fold(pattern[p]) else null;
        if (pc) |c| {
            if (c == '*') {
                star_p = p;
                p += 1;
                star_n = n;
                continue;
            }
            if (c == '?' or std.ascii.toLower(c) == std.ascii.toLower(name[n])) {
                p += 1;
                n += 1;
                continue;
            }
        }
        if (star_p) |sp| {
            p = sp + 1;
            star_n += 1;
            n = star_n;
            continue;
        }
        return false;
    }
    while (p < pattern.len and fold(pattern[p]) == '*') p += 1;
    return p == pattern.len;
}

fn fold(c: u8) u8 {
    return switch (c) {
        '<' => '*',
        '>' => '?',
        '"' => '.',
        else => c,
    };
}

const testing = std.testing;

test "utf16 round-trip including a surrogate pair" {
    var wide: [64]u8 = undefined;
    var narrow: [64]u8 = undefined;
    const text = "naïve/😀.txt";
    const encoded = try toUtf16le(&wide, text);
    try testing.expectEqual(try utf16leLen(text), encoded.len);
    try testing.expectEqualStrings(text, try toUtf8(&narrow, encoded));
}

test "utf16 rejects odd lengths and lone surrogates" {
    var out: [64]u8 = undefined;
    try testing.expectError(error.BadEncoding, toUtf8(&out, &.{0x41}));
    try testing.expectError(error.BadEncoding, toUtf8(&out, &.{ 0x00, 0xD8 })); // high, no low
    try testing.expectError(error.BadEncoding, toUtf8(&out, &.{ 0x00, 0xDC })); // lone low
}

test "normalizePath: backslashes become slashes, root is empty" {
    var out: [max_path]u8 = undefined;
    try testing.expectEqualStrings("a/b/c.txt", try normalizePath(&out, "a\\b\\c.txt"));
    try testing.expectEqualStrings("a/b", try normalizePath(&out, "\\a\\\\b\\"));
    try testing.expectEqualStrings("", try normalizePath(&out, ""));
    try testing.expectEqualStrings("", try normalizePath(&out, "\\"));
    try testing.expectEqualStrings("x", try normalizePath(&out, ".\\x"));
}

test "normalizePath: escapes and stream suffixes are refused" {
    var out: [max_path]u8 = undefined;
    try testing.expectError(error.BadPath, normalizePath(&out, "..\\etc\\passwd"));
    try testing.expectError(error.BadPath, normalizePath(&out, "a\\..\\..\\b"));
    try testing.expectError(error.BadPath, normalizePath(&out, "a\\b\x00c"));
    try testing.expectError(error.BadPath, normalizePath(&out, "file.txt:$DATA"));
    try testing.expectError(error.BadPath, normalizePath(&out, "..."));
}

test "normalizePath: trailing dots and spaces are stripped like Windows does" {
    var out: [max_path]u8 = undefined;
    // Without this, `secret.txt.` and `secret.txt ` would be two distinct
    // names to us and one name to every Windows client.
    try testing.expectEqualStrings("secret.txt", try normalizePath(&out, "secret.txt."));
    try testing.expectEqualStrings("a/b", try normalizePath(&out, "a \\b  "));
}

test "matchWildcard: the patterns clients actually send" {
    try testing.expect(matchWildcard("*", "anything"));
    try testing.expect(matchWildcard("*.txt", "notes.TXT"));
    try testing.expect(!matchWildcard("*.txt", "notes.txtx"));
    try testing.expect(matchWildcard("a?c", "abc"));
    try testing.expect(!matchWildcard("a?c", "ac"));
    try testing.expect(matchWildcard("*a*b*", "xxayybzz"));
    try testing.expect(matchWildcard("<", "anything")); // DOS_STAR
    try testing.expect(matchWildcard("file>.txt", "fileX.txt")); // DOS_QM
    try testing.expect(matchWildcard("", ""));
    try testing.expect(!matchWildcard("", "x"));
}

test "baseName and dirName split a normalized path" {
    try testing.expectEqualStrings("c.txt", baseName("a/b/c.txt"));
    try testing.expectEqualStrings("a/b", dirName("a/b/c.txt"));
    try testing.expectEqualStrings("solo", baseName("solo"));
    try testing.expectEqualStrings("", dirName("solo"));
}
