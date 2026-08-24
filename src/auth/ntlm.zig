//! NTLMSSP (MS-NLMP): the three-message challenge/response every SMB client
//! still speaks. Only NTLMv2 is accepted — an NTLMv1 response (24 bytes flat)
//! is refused rather than downgraded, because v1 is trivially crackable from a
//! passive capture and no client from this decade needs it.
//!
//! Nothing here allocates: names are decoded into a caller-owned `Names` and
//! messages are built into a caller-owned buffer.

const std = @import("std");
const wire = @import("../smb/wire.zig");
const md4 = @import("md4.zig");
const rc4 = @import("rc4.zig");
const unicode = @import("../smb/unicode.zig");
const filetime = @import("../smb/time.zig");

const HmacMd5 = std.crypto.auth.hmac.HmacMd5;

pub const Error = error{
    /// Not an NTLMSSP message, or one whose fields point outside it.
    Malformed,
    /// A message type we do not implement (there is no type 4).
    Unsupported,
    /// NTLMv1, a null session, or otherwise a response we refuse to evaluate.
    Refused,
} || wire.Error || unicode.Error;

pub const signature = "NTLMSSP\x00";

pub const MessageType = enum(u32) {
    negotiate = 1,
    challenge = 2,
    authenticate = 3,
    _,
};

pub const flags = struct {
    pub const UNICODE: u32 = 0x0000_0001;
    pub const OEM: u32 = 0x0000_0002;
    pub const REQUEST_TARGET: u32 = 0x0000_0004;
    pub const SIGN: u32 = 0x0000_0010;
    pub const SEAL: u32 = 0x0000_0020;
    pub const NTLM: u32 = 0x0000_0200;
    pub const ANONYMOUS: u32 = 0x0000_0800;
    pub const DOMAIN_SUPPLIED: u32 = 0x0000_1000;
    pub const WORKSTATION_SUPPLIED: u32 = 0x0000_2000;
    pub const ALWAYS_SIGN: u32 = 0x0000_8000;
    pub const TARGET_TYPE_DOMAIN: u32 = 0x0001_0000;
    pub const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
    pub const EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    pub const TARGET_INFO: u32 = 0x0080_0000;
    pub const VERSION: u32 = 0x0200_0000;
    pub const KEY_128: u32 = 0x2000_0000;
    pub const KEY_EXCH: u32 = 0x4000_0000;
    pub const KEY_56: u32 = 0x8000_0000;
};

pub const av = struct {
    pub const EOL: u16 = 0;
    pub const NB_COMPUTER_NAME: u16 = 1;
    pub const NB_DOMAIN_NAME: u16 = 2;
    pub const DNS_COMPUTER_NAME: u16 = 3;
    pub const DNS_DOMAIN_NAME: u16 = 4;
    pub const TIMESTAMP: u16 = 7;
    pub const FLAGS: u16 = 6;
    pub const SINGLE_HOST: u16 = 8;
    pub const TARGET_NAME: u16 = 9;
    pub const CHANNEL_BINDINGS: u16 = 10;
};

pub fn isNtlmssp(bytes: []const u8) bool {
    return bytes.len >= 12 and std.mem.eql(u8, bytes[0..8], signature);
}

pub fn messageType(bytes: []const u8) ?MessageType {
    if (!isNtlmssp(bytes)) return null;
    return @enumFromInt(std.mem.readInt(u32, bytes[8..12], .little));
}

/// The NT hash: MD4 over the password in UTF-16LE. This is the only secret a
/// credential adapter has to hold, and holding it is equivalent to holding the
/// password — it is a password-equivalent, not a salted hash.
pub fn ntHash(password_utf8: []const u8) unicode.Error![16]u8 {
    var wide: [512]u8 = undefined;
    const encoded = try unicode.toUtf16le(&wide, password_utf8);
    var out: [16]u8 = undefined;
    md4.Md4.hash(encoded, &out);
    std.crypto.secureZero(u8, &wide);
    return out;
}

/// NTOWFv2 = HMAC_MD5(NT hash, UPPER(user) ++ domain) over UTF-16LE. The
/// uppercasing is ASCII-only, matching what Windows does for every account name
/// that is not scripted in a cased non-Latin alphabet.
pub fn responseKey(nt_hash: [16]u8, user_utf8: []const u8, domain_utf8: []const u8) unicode.Error![16]u8 {
    var upper: [unicode.max_name]u8 = undefined;
    if (user_utf8.len > upper.len) return error.NoSpace;
    for (user_utf8, 0..) |ch, i| upper[i] = std.ascii.toUpper(ch);

    var wide: [unicode.max_name * 4]u8 = undefined;
    const u16_user = try unicode.toUtf16le(&wide, upper[0..user_utf8.len]);
    const u16_domain = try unicode.toUtf16le(wide[u16_user.len..], domain_utf8);

    var mac = HmacMd5.init(&nt_hash);
    mac.update(u16_user);
    mac.update(u16_domain);
    var out: [16]u8 = undefined;
    mac.final(&out);
    return out;
}

pub const ChallengeOptions = struct {
    challenge: [8]u8,
    /// Advertised as the target and as the NetBIOS names in the AV pairs.
    /// Clients bind the AV pairs into their NTLMv2 blob, so these end up
    /// covered by the response — they are not decoration.
    netbios_name: []const u8,
    domain: []const u8,
    dns_name: []const u8 = "",
    dns_domain: []const u8 = "",
    /// Echoed back from the client's NEGOTIATE, narrowed to what we support.
    client_flags: u32 = 0,
};

/// Builds the CHALLENGE (type 2) message into `out`.
pub fn buildChallenge(out: []u8, opts: ChallengeOptions) Error![]u8 {
    var w = wire.Writer.init(out);

    var negotiate = flags.UNICODE | flags.REQUEST_TARGET | flags.NTLM |
        flags.ALWAYS_SIGN | flags.TARGET_TYPE_SERVER | flags.TARGET_INFO |
        flags.EXTENDED_SESSIONSECURITY | flags.KEY_128;
    // KEY_EXCH and SIGN/SEAL are only meaningful if the client asked; echoing
    // them back when it did not makes some clients seal a key we never see.
    negotiate |= opts.client_flags & (flags.KEY_EXCH | flags.SIGN | flags.SEAL | flags.KEY_56);

    try w.blob(signature);
    try w.u32_(@intFromEnum(MessageType.challenge));

    const target_fields = w.pos;
    try w.zeroes(8); // TargetName security buffer, patched below
    try w.u32_(negotiate);
    try w.blob(&opts.challenge);
    try w.zeroes(8); // Reserved
    const info_fields = w.pos;
    try w.zeroes(8); // TargetInfo security buffer, patched below
    try w.zeroes(8); // Version — omitted; we never set NEGOTIATE_VERSION

    const target_at = w.pos;
    const target = try unicode.toUtf16le(try w.reserve(try unicode.utf16leLen(opts.netbios_name)), opts.netbios_name);
    try patchField(&w, target_fields, target.len, target_at);

    const info_at = w.pos;
    try writeAv(&w, av.NB_DOMAIN_NAME, opts.domain);
    try writeAv(&w, av.NB_COMPUTER_NAME, opts.netbios_name);
    if (opts.dns_domain.len > 0) try writeAv(&w, av.DNS_DOMAIN_NAME, opts.dns_domain);
    if (opts.dns_name.len > 0) try writeAv(&w, av.DNS_COMPUTER_NAME, opts.dns_name);
    // The timestamp is what lets a client bind its response to a moment; Windows
    // clients omit their MIC when the server omits this.
    try w.u16_(av.TIMESTAMP);
    try w.u16_(8);
    try w.u64_(filetime.now());
    try w.u16_(av.EOL);
    try w.u16_(0);
    try patchField(&w, info_fields, w.pos - info_at, info_at);

    return w.written();
}

fn writeAv(w: *wire.Writer, id: u16, value_utf8: []const u8) Error!void {
    const len = try unicode.utf16leLen(value_utf8);
    try w.u16_(id);
    try w.u16_(@intCast(len));
    _ = try unicode.toUtf16le(try w.reserve(len), value_utf8);
}

fn patchField(w: *wire.Writer, at: usize, len: usize, offset: usize) Error!void {
    try w.patchInt(u16, at, @intCast(len));
    try w.patchInt(u16, at + 2, @intCast(len));
    try w.patchInt(u32, at + 4, @intCast(offset));
}

/// Scratch for the three names an AUTHENTICATE carries, decoded to UTF-8.
pub const Names = struct {
    domain: [unicode.max_name]u8 = undefined,
    user: [unicode.max_name]u8 = undefined,
    workstation: [unicode.max_name]u8 = undefined,
};

pub const Authenticate = struct {
    domain: []const u8,
    user: []const u8,
    workstation: []const u8,
    lm_response: []const u8,
    nt_response: []const u8,
    encrypted_session_key: []const u8,
    negotiate_flags: u32,
    /// Present only when the client left room for it; when present it covers
    /// all three messages and proves the exchange was not tampered with.
    mic: ?[16]u8,
    mic_offset: usize,

    pub fn isAnonymous(a: Authenticate) bool {
        return a.user.len == 0 or a.nt_response.len == 0 or
            a.negotiate_flags & flags.ANONYMOUS != 0;
    }
};

/// Parses an AUTHENTICATE (type 3), decoding its names into `names`.
pub fn parseAuthenticate(msg: []const u8, names: *Names) Error!Authenticate {
    if (messageType(msg) != .authenticate) return error.Malformed;
    var r = wire.Reader.init(msg);
    try r.skip(12);

    const lm = try readField(&r, msg);
    const nt = try readField(&r, msg);
    const domain = try readField(&r, msg);
    const user = try readField(&r, msg);
    const workstation = try readField(&r, msg);
    const session_key = try readField(&r, msg);
    const negotiate_flags = try r.u32_();

    // Everything past the fixed 64-byte prologue is optional: Version (8) then
    // MIC (16). A field only exists if the payload starts after it, which is
    // how MS-NLMP tells a short header from a long one.
    var payload_start: usize = msg.len;
    for ([_][]const u8{ lm, nt, domain, user, workstation, session_key }) |field| {
        if (field.len == 0) continue;
        const offset = @intFromPtr(field.ptr) - @intFromPtr(msg.ptr);
        payload_start = @min(payload_start, offset);
    }

    var mic: ?[16]u8 = null;
    var mic_offset: usize = 0;
    if (payload_start >= 72 + 16 and msg.len >= 88) {
        mic_offset = 72;
        mic = msg[72..88].*;
    }

    if (domain.len > names.domain.len or user.len > names.user.len) return error.Malformed;

    const unicode_names = negotiate_flags & flags.UNICODE != 0;
    return .{
        .domain = try decodeName(&names.domain, domain, unicode_names),
        .user = try decodeName(&names.user, user, unicode_names),
        .workstation = try decodeName(&names.workstation, workstation, unicode_names),
        .lm_response = lm,
        .nt_response = nt,
        .encrypted_session_key = session_key,
        .negotiate_flags = negotiate_flags,
        .mic = mic,
        .mic_offset = mic_offset,
    };
}

/// The negotiate flags a client offers; the only field of a type 1 we use.
pub fn parseNegotiateFlags(msg: []const u8) Error!u32 {
    if (messageType(msg) != .negotiate) return error.Malformed;
    if (msg.len < 16) return error.Malformed;
    return std.mem.readInt(u32, msg[12..16], .little);
}

fn readField(r: *wire.Reader, msg: []const u8) Error![]const u8 {
    const len = try r.u16_();
    _ = try r.u16_(); // MaxLen, ignored: clients set it equal to Len
    const offset = try r.u32_();
    if (len == 0) return msg[0..0];
    if (offset > msg.len or msg.len - offset < len) return error.Malformed;
    return msg[offset..][0..len];
}

fn decodeName(out: []u8, raw: []const u8, is_unicode: bool) Error![]const u8 {
    if (!is_unicode) {
        // OEM names are effectively ASCII here; anything else is unmappable
        // without a codepage table we deliberately do not carry.
        if (raw.len > out.len) return error.NoSpace;
        @memcpy(out[0..raw.len], raw);
        return out[0..raw.len];
    }
    return unicode.toUtf8(out, raw);
}

pub const Session = struct {
    /// The key SMB2 signs with (and, for SMB3, derives every other key from).
    session_key: [16]u8,
};

pub const VerifyInput = struct {
    nt_hash: [16]u8,
    server_challenge: [8]u8,
    auth: Authenticate,
    /// The raw type 1 and type 2 messages, kept only so the MIC can be checked.
    negotiate_message: []const u8 = &.{},
    challenge_message: []const u8 = &.{},
    /// The raw type 3 exactly as received (the MIC covers it with the MIC
    /// field zeroed).
    authenticate_message: []const u8 = &.{},
};

/// Verifies an NTLMv2 response and derives the SMB session key.
/// Returns `error.Refused` for anything that is not a checkable v2 response —
/// including a null session, which this server never accepts.
pub fn verify(in: VerifyInput) Error!Session {
    const auth = in.auth;
    if (auth.isAnonymous()) return error.Refused;
    // NTLMv2 responses are NTProofStr(16) ++ blob; a bare 24 bytes is v1.
    if (auth.nt_response.len <= 24) return error.Refused;

    const key = try responseKey(in.nt_hash, auth.user, auth.domain);
    const proof = auth.nt_response[0..16];
    const blob = auth.nt_response[16..];

    var mac = HmacMd5.init(&key);
    mac.update(&in.server_challenge);
    mac.update(blob);
    var expected: [16]u8 = undefined;
    mac.final(&expected);
    if (!std.crypto.timing_safe.eql([16]u8, expected, proof[0..16].*)) return error.Refused;

    var base_key: [16]u8 = undefined;
    HmacMd5.create(&base_key, proof, &key);

    var session_key = base_key;
    if (auth.negotiate_flags & flags.KEY_EXCH != 0 and auth.encrypted_session_key.len == 16) {
        @memcpy(&session_key, auth.encrypted_session_key);
        rc4.Rc4.oneShot(&base_key, &session_key);
    }

    if (auth.mic) |claimed| {
        if (in.authenticate_message.len >= auth.mic_offset + 16 and in.challenge_message.len > 0) {
            var computed: [16]u8 = undefined;
            var m = HmacMd5.init(&session_key);
            m.update(in.negotiate_message);
            m.update(in.challenge_message);
            m.update(in.authenticate_message[0..auth.mic_offset]);
            m.update(&[_]u8{0} ** 16);
            m.update(in.authenticate_message[auth.mic_offset + 16 ..]);
            m.final(&computed);
            if (!std.crypto.timing_safe.eql([16]u8, computed, claimed)) return error.Refused;
        }
    }

    return .{ .session_key = session_key };
}

/// Builds an NTLMv2 AUTHENTICATE the way a client would. Only the tests use it,
/// but they are the only end-to-end check that `verify` accepts a real client's
/// arithmetic rather than merely its own.
pub fn buildAuthenticateForTest(
    out: []u8,
    nt_hash: [16]u8,
    user: []const u8,
    domain: []const u8,
    server_challenge: [8]u8,
    client_blob: []const u8,
) Error![]u8 {
    const key = try responseKey(nt_hash, user, domain);
    var proof: [16]u8 = undefined;
    var mac = HmacMd5.init(&key);
    mac.update(&server_challenge);
    mac.update(client_blob);
    mac.final(&proof);

    var w = wire.Writer.init(out);
    try w.blob(signature);
    try w.u32_(@intFromEnum(MessageType.authenticate));
    const fields = w.pos;
    try w.zeroes(8 * 6);
    try w.u32_(flags.UNICODE | flags.NTLM | flags.EXTENDED_SESSIONSECURITY);
    try w.zeroes(8); // Version
    // No MIC: leaving the payload to start at 72 is how a client says so.

    const nt_at = w.pos;
    try w.blob(&proof);
    try w.blob(client_blob);
    try patchField(&w, fields + 8, 16 + client_blob.len, nt_at);

    const domain_at = w.pos;
    _ = try unicode.toUtf16le(try w.reserve(try unicode.utf16leLen(domain)), domain);
    try patchField(&w, fields + 16, w.pos - domain_at, domain_at);

    const user_at = w.pos;
    _ = try unicode.toUtf16le(try w.reserve(try unicode.utf16leLen(user)), user);
    try patchField(&w, fields + 24, w.pos - user_at, user_at);

    return w.written();
}

const testing = std.testing;

test "NT hash of a known password" {
    // The MD4 of UTF-16LE "password"; every NTLM implementation agrees on this
    // one, which makes it the anchor for everything below.
    const h = try ntHash("password");
    var hex: [32]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&h}) catch unreachable;
    try testing.expectEqualStrings("8846f7eaee8fb117ad06bdd830b7586c", &hex);
}

test "MS-NLMP 4.2.4 NTOWFv2 sample" {
    // MS-NLMP's own worked example: user "User", domain "Domain",
    // password "Password".
    const h = try ntHash("Password");
    const key = try responseKey(h, "User", "Domain");
    var hex: [32]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&key}) catch unreachable;
    try testing.expectEqualStrings("0c868a403bfd7a93a3001ef22ef02e3f", &hex);
}

test "verify accepts a well-formed v2 response and derives a session key" {
    const h = try ntHash("Password");
    const challenge = [8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    const blob = [_]u8{ 0x01, 0x01, 0, 0, 0, 0, 0, 0 } ++ [_]u8{0xAA} ** 24;

    var buf: [512]u8 = undefined;
    const msg = try buildAuthenticateForTest(&buf, h, "User", "Domain", challenge, &blob);

    var names: Names = .{};
    const auth = try parseAuthenticate(msg, &names);
    try testing.expectEqualStrings("User", auth.user);
    try testing.expectEqualStrings("Domain", auth.domain);

    const session = try verify(.{ .nt_hash = h, .server_challenge = challenge, .auth = auth });
    // SessionBaseKey = HMAC_MD5(NTOWFv2, NTProofStr) — recompute independently.
    const key = try responseKey(h, "User", "Domain");
    var expected: [16]u8 = undefined;
    HmacMd5.create(&expected, auth.nt_response[0..16], &key);
    try testing.expectEqualSlices(u8, &expected, &session.session_key);
}

test "verify refuses a wrong password, NTLMv1 and null sessions" {
    const h = try ntHash("Password");
    const wrong = try ntHash("Passw0rd");
    const challenge = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const blob = [_]u8{0x55} ** 28;

    var buf: [512]u8 = undefined;
    const msg = try buildAuthenticateForTest(&buf, h, "User", "Domain", challenge, &blob);
    var names: Names = .{};
    var auth = try parseAuthenticate(msg, &names);

    try testing.expectError(error.Refused, verify(.{
        .nt_hash = wrong,
        .server_challenge = challenge,
        .auth = auth,
    }));

    // A different challenge is the replay case: same response, new challenge.
    try testing.expectError(error.Refused, verify(.{
        .nt_hash = h,
        .server_challenge = .{ 9, 9, 9, 9, 9, 9, 9, 9 },
        .auth = auth,
    }));

    auth.nt_response = auth.nt_response[0..24]; // NTLMv1-shaped
    try testing.expectError(error.Refused, verify(.{
        .nt_hash = h,
        .server_challenge = challenge,
        .auth = auth,
    }));

    auth.nt_response = &.{}; // null session
    try testing.expect(auth.isAnonymous());
    try testing.expectError(error.Refused, verify(.{
        .nt_hash = h,
        .server_challenge = challenge,
        .auth = auth,
    }));
}

test "buildChallenge lays out a parseable type 2" {
    var buf: [512]u8 = undefined;
    const msg = try buildChallenge(&buf, .{
        .challenge = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .netbios_name = "EASYSAMBA",
        .domain = "WORKGROUP",
        .client_flags = flags.KEY_EXCH,
    });
    try testing.expectEqual(MessageType.challenge, messageType(msg).?);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, msg[24..32]);

    const negotiate = std.mem.readInt(u32, msg[20..24], .little);
    try testing.expect(negotiate & flags.UNICODE != 0);
    try testing.expect(negotiate & flags.TARGET_INFO != 0);
    try testing.expect(negotiate & flags.KEY_EXCH != 0); // echoed back

    // TargetInfo must be inside the message and end with an EOL pair.
    const info_len = std.mem.readInt(u16, msg[40..42], .little);
    const info_off = std.mem.readInt(u32, msg[44..48], .little);
    try testing.expect(info_off + info_len <= msg.len);
    const info = msg[info_off..][0..info_len];
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, info[info.len - 4 ..]);
}

test "buildChallenge omits KEY_EXCH when the client never asked" {
    var buf: [512]u8 = undefined;
    const msg = try buildChallenge(&buf, .{
        .challenge = @splat(0),
        .netbios_name = "EASYSAMBA",
        .domain = "WORKGROUP",
    });
    const negotiate = std.mem.readInt(u32, msg[20..24], .little);
    try testing.expect(negotiate & flags.KEY_EXCH == 0);
}

test "parseAuthenticate rejects fields pointing outside the message" {
    var msg: [72]u8 = @splat(0);
    @memcpy(msg[0..8], signature);
    std.mem.writeInt(u32, msg[8..12], 3, .little);
    std.mem.writeInt(u16, msg[20..22], 64, .little); // NtResponse len
    std.mem.writeInt(u32, msg[24..28], 0xFFFF, .little); // ...at a bogus offset
    var names: Names = .{};
    try testing.expectError(error.Malformed, parseAuthenticate(&msg, &names));
}
