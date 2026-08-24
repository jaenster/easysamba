//! Just enough SPNEGO (RFC 4178) to carry NTLMSSP, plus the DER cursor it needs.
//!
//! A full GSS-API stack this is not: the server advertises exactly one
//! mechanism, so the parse side only has to find the NTLM token inside whatever
//! wrapper a client chose — raw NTLMSSP, a GSS-API `InitialContextToken`, a
//! bare `NegTokenInit`, or a `NegTokenResp` — and the build side only has to
//! emit the two replies that mechanism needs.

const std = @import("std");
const ntlm = @import("ntlm.zig");

pub const Error = error{ Malformed, NoSpace };

/// 1.3.6.1.5.5.2
pub const spnego_oid = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
/// 1.3.6.1.4.1.311.2.2.10
pub const ntlmssp_oid = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };

const tag_octet_string: u8 = 0x04;
const tag_oid: u8 = 0x06;
const constructed: u8 = 0x20;

pub const NegResult = enum(u8) {
    accept_completed = 0,
    accept_incomplete = 1,
    reject = 2,
};

/// Finds the NTLMSSP message inside a SESSION_SETUP security buffer.
///
/// The search descends through constructed DER elements and OCTET STRINGs
/// rather than matching one exact grammar, because clients differ on which
/// wrapper they use and on whether a `mechToken` is wrapped once or twice. That
/// leniency is safe here: the payload is still validated as NTLMSSP, and the
/// NTLM layer treats every byte of it as hostile regardless.
pub fn findNtlmToken(blob: []const u8) ?[]const u8 {
    if (ntlm.isNtlmssp(blob)) return blob;
    return search(blob, 0);
}

fn search(bytes: []const u8, depth: u8) ?[]const u8 {
    if (depth > 8) return null;
    var cursor = Der{ .bytes = bytes };
    while (cursor.next() catch return null) |el| {
        if (ntlm.isNtlmssp(el.value)) return el.value;
        const descend = el.tag & constructed != 0 or el.tag == tag_octet_string;
        if (descend) {
            if (search(el.value, depth + 1)) |found| return found;
        }
    }
    return null;
}

/// The server's `negTokenInit`, sent in the NEGOTIATE response: "I speak
/// NTLMSSP, and nothing else."
pub fn buildNegTokenInit(out: []u8) Error![]u8 {
    var mech_list: [32]u8 = undefined;
    const oid = try wrap(&mech_list, tag_oid, &ntlmssp_oid);
    var mech_seq: [40]u8 = undefined;
    const seq = try wrap(&mech_seq, 0x30, oid);
    var mech_types: [48]u8 = undefined;
    const types = try wrap(&mech_types, 0xa0, seq);
    var init_seq: [56]u8 = undefined;
    const inner = try wrap(&init_seq, 0x30, types);
    var neg: [64]u8 = undefined;
    const neg_token = try wrap(&neg, 0xa0, inner);

    // The GSS-API InitialContextToken: [APPLICATION 0] { OID, NegTokenInit }.
    const body_len = 2 + spnego_oid.len + neg_token.len;
    if (out.len < body_len + 4) return error.NoSpace;
    var w: usize = 0;
    out[w] = 0x60;
    w += 1;
    w += writeLen(out[w..], body_len);
    out[w] = tag_oid;
    out[w + 1] = @intCast(spnego_oid.len);
    w += 2;
    @memcpy(out[w..][0..spnego_oid.len], &spnego_oid);
    w += spnego_oid.len;
    @memcpy(out[w..][0..neg_token.len], neg_token);
    w += neg_token.len;
    return out[0..w];
}

/// The server's `negTokenResp`. `mech` is only sent with the first reply, as
/// RFC 4178 requires (repeating it on the final accept confuses some clients).
pub fn buildNegTokenResp(out: []u8, result: NegResult, include_mech: bool, response_token: []const u8) Error![]u8 {
    var scratch: [4096]u8 = undefined;
    var inner_len: usize = 0;

    {
        const state = [_]u8{ 0x0a, 0x01, @intFromEnum(result) };
        inner_len += (try wrap(scratch[inner_len..], 0xa0, &state)).len;
    }
    if (include_mech) {
        var oid_buf: [16]u8 = undefined;
        const oid = try wrap(&oid_buf, tag_oid, &ntlmssp_oid);
        inner_len += (try wrap(scratch[inner_len..], 0xa1, oid)).len;
    }
    if (response_token.len > 0) {
        var octet: [3072]u8 = undefined;
        const wrapped = try wrap(&octet, tag_octet_string, response_token);
        inner_len += (try wrap(scratch[inner_len..], 0xa2, wrapped)).len;
    }

    var seq: [4096]u8 = undefined;
    const sequence = try wrap(&seq, 0x30, scratch[0..inner_len]);
    return wrap(out, 0xa1, sequence);
}

/// Emits one `tag { value }` element into `buf` and returns the bytes written.
fn wrap(buf: []u8, tag: u8, value: []const u8) Error![]u8 {
    const header = 1 + lenSize(value.len);
    if (buf.len < header + value.len) return error.NoSpace;
    buf[0] = tag;
    const n = writeLen(buf[1..], value.len);
    @memcpy(buf[1 + n ..][0..value.len], value);
    return buf[0 .. 1 + n + value.len];
}

fn lenSize(len: usize) usize {
    if (len < 0x80) return 1;
    if (len <= 0xFF) return 2;
    if (len <= 0xFFFF) return 3;
    return 4;
}

fn writeLen(buf: []u8, len: usize) usize {
    if (len < 0x80) {
        buf[0] = @intCast(len);
        return 1;
    }
    if (len <= 0xFF) {
        buf[0] = 0x81;
        buf[1] = @intCast(len);
        return 2;
    }
    if (len <= 0xFFFF) {
        buf[0] = 0x82;
        buf[1] = @intCast(len >> 8);
        buf[2] = @truncate(len);
        return 3;
    }
    buf[0] = 0x83;
    buf[1] = @intCast(len >> 16);
    buf[2] = @truncate(len >> 8);
    buf[3] = @truncate(len);
    return 4;
}

pub const Element = struct {
    tag: u8,
    value: []const u8,
};

/// A forward-only DER walker over one level of TLVs. Indefinite lengths are
/// rejected: they cannot appear in DER, and accepting them is how ASN.1 parsers
/// end up reading past their buffer.
pub const Der = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(d: *Der) Error!?Element {
        if (d.pos >= d.bytes.len) return null;
        const tag = d.bytes[d.pos];
        var p = d.pos + 1;
        if (p >= d.bytes.len) return error.Malformed;

        var len: usize = d.bytes[p];
        p += 1;
        if (len & 0x80 != 0) {
            const count = len & 0x7F;
            if (count == 0 or count > 4) return error.Malformed; // indefinite or absurd
            if (d.bytes.len - p < count) return error.Malformed;
            len = 0;
            for (d.bytes[p..][0..count]) |byte| len = (len << 8) | byte;
            p += count;
        }
        if (d.bytes.len - p < len) return error.Malformed;
        d.pos = p + len;
        return .{ .tag = tag, .value = d.bytes[p..][0..len] };
    }
};

const testing = std.testing;

test "findNtlmToken: a raw NTLMSSP message passes straight through" {
    const raw = ntlm.signature ++ [_]u8{ 1, 0, 0, 0 } ++ [_]u8{0} ** 20;
    try testing.expectEqualSlices(u8, raw, findNtlmToken(raw).?);
}

test "findNtlmToken: unwraps a GSS-API negTokenInit carrying a mechToken" {
    const token = ntlm.signature ++ [_]u8{ 1, 0, 0, 0 } ++ [_]u8{0xAB} ** 32;

    // Hand-build what a client sends: 0x60 { SPNEGO OID, [0] { SEQUENCE {
    //   [0] mechTypes, [2] { OCTET STRING mechToken } } } }
    var mech_oid: [16]u8 = undefined;
    var mech_seq: [24]u8 = undefined;
    var mech_types: [32]u8 = undefined;
    var octet: [128]u8 = undefined;
    var mech_token: [128]u8 = undefined;
    var inner: [256]u8 = undefined;
    var neg: [256]u8 = undefined;
    var out: [512]u8 = undefined;

    const types = try wrap(&mech_types, 0xa0, try wrap(&mech_seq, 0x30, try wrap(&mech_oid, tag_oid, &ntlmssp_oid)));
    const tok = try wrap(&mech_token, 0xa2, try wrap(&octet, tag_octet_string, token));
    var body: [256]u8 = undefined;
    @memcpy(body[0..types.len], types);
    @memcpy(body[types.len..][0..tok.len], tok);
    const neg_token = try wrap(&neg, 0xa0, try wrap(&inner, 0x30, body[0 .. types.len + tok.len]));

    var w: usize = 0;
    out[0] = 0x60;
    w = 1 + writeLen(out[1..], 2 + spnego_oid.len + neg_token.len);
    out[w] = tag_oid;
    out[w + 1] = spnego_oid.len;
    @memcpy(out[w + 2 ..][0..spnego_oid.len], &spnego_oid);
    w += 2 + spnego_oid.len;
    @memcpy(out[w..][0..neg_token.len], neg_token);
    w += neg_token.len;

    try testing.expectEqualSlices(u8, token, findNtlmToken(out[0..w]).?);
}

test "findNtlmToken: unwraps a negTokenResp responseToken" {
    const token = ntlm.signature ++ [_]u8{ 3, 0, 0, 0 } ++ [_]u8{0xCD} ** 64;
    var out: [512]u8 = undefined;
    const resp = try buildNegTokenResp(&out, .accept_incomplete, true, token);
    try testing.expectEqualSlices(u8, token, findNtlmToken(resp).?);
}

test "findNtlmToken: returns null rather than guessing" {
    try testing.expect(findNtlmToken("") == null);
    try testing.expect(findNtlmToken(&.{ 0x30, 0x03, 0x02, 0x01, 0x05 }) == null);
    try testing.expect(findNtlmToken(&.{ 0x30, 0x82, 0xFF, 0xFF }) == null); // lying length
}

test "buildNegTokenInit advertises NTLMSSP and only NTLMSSP" {
    var out: [128]u8 = undefined;
    const blob = try buildNegTokenInit(&out);
    try testing.expectEqual(@as(u8, 0x60), blob[0]);
    try testing.expect(std.mem.indexOf(u8, blob, &spnego_oid) != null);
    try testing.expect(std.mem.indexOf(u8, blob, &ntlmssp_oid) != null);
    // One mechanism means the OID appears exactly once.
    const first = std.mem.indexOf(u8, blob, &ntlmssp_oid).?;
    try testing.expect(std.mem.indexOf(u8, blob[first + 1 ..], &ntlmssp_oid) == null);

    // And it must parse as one complete element with nothing trailing.
    var der = Der{ .bytes = blob };
    const outer = (try der.next()).?;
    try testing.expectEqual(@as(u8, 0x60), outer.tag);
    try testing.expect((try der.next()) == null);
}

test "buildNegTokenResp: the final accept carries no mech and no token" {
    var out: [64]u8 = undefined;
    const blob = try buildNegTokenResp(&out, .accept_completed, false, &.{});
    try testing.expectEqual(@as(u8, 0xa1), blob[0]);
    try testing.expect(std.mem.indexOf(u8, blob, &ntlmssp_oid) == null);

    var der = Der{ .bytes = blob };
    const outer = (try der.next()).?;
    var seq = Der{ .bytes = outer.value };
    const inner = (try seq.next()).?;
    try testing.expectEqual(@as(u8, 0x30), inner.tag);
    var fields = Der{ .bytes = inner.value };
    const state = (try fields.next()).?;
    try testing.expectEqual(@as(u8, 0xa0), state.tag);
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0x01, 0x00 }, state.value); // accept-completed
    try testing.expect((try fields.next()) == null);
}

test "Der: long-form lengths and overruns" {
    var long: [260]u8 = undefined;
    long[0] = 0x04;
    long[1] = 0x82;
    long[2] = 0x01;
    long[3] = 0x00; // 256 bytes
    var der = Der{ .bytes = &long };
    const el = (try der.next()).?;
    try testing.expectEqual(@as(usize, 256), el.value.len);

    var truncated = Der{ .bytes = &.{ 0x04, 0x05, 1, 2 } };
    try testing.expectError(error.Malformed, truncated.next());

    var indefinite = Der{ .bytes = &.{ 0x30, 0x80, 0x00, 0x00 } };
    try testing.expectError(error.Malformed, indefinite.next());
}
