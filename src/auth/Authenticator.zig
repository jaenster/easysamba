//! The credential adapter interface.
//!
//! Same shape as the share adapter: a vtable and an opaque context, so accounts
//! can come from a config string, a file, a database, whatever gets written
//! next. Nothing here allocates and nothing may block for long.
//!
//! The interface hands back an NT hash rather than a yes/no verdict on a
//! password, because NTLMv2 leaves no choice: the client never sends the
//! password, it sends an HMAC keyed by the NT hash, so the server must hold the
//! hash to check it. Two consequences worth being blunt about:
//!
//!   * An NT hash is password-equivalent. Storing one is storing the password.
//!   * A backend that cannot produce the hash (a domain controller, PAM, an
//!     OAuth provider) cannot be adapted this way — it would need a vtable
//!     entry that takes the whole NTLMv2 response and returns a session key,
//!     which is the natural place to extend this when such a backend appears.
//!
//! There is no guest, anonymous or null-session path anywhere in this server:
//! a lookup that fails is a refused logon, full stop.

const std = @import("std");
const ntlm = @import("ntlm.zig");
const unicode = @import("../smb/unicode.zig");

pub const Account = struct {
    /// MD4 of the password in UTF-16LE.
    nt_hash: [16]u8,
    /// This account may not write to any share, whatever the share allows.
    read_only: bool = false,
    /// Passed to nothing yet; carried so an adapter can tag an identity for a
    /// share adapter that cares who is asking.
    uid: u32 = 0,
};

pub const VTable = struct {
    /// Case-insensitive on the user name. `domain` is whatever the client sent
    /// and may be empty; an adapter that does not care should ignore it rather
    /// than reject on it, because clients send the workstation name, the
    /// server name, or nothing at all.
    lookup: *const fn (ctx: *anyopaque, user: []const u8, domain: []const u8) ?Account,
};

pub const Authenticator = @This();

ctx: *anyopaque,
vtable: *const VTable,

pub fn lookup(a: Authenticator, user: []const u8, domain: []const u8) ?Account {
    if (user.len == 0) return null; // a null session is never an account
    return a.vtable.lookup(a.ctx, user, domain);
}

/// A fixed-capacity account table, configured from a string.
///
/// Format, one account per line or comma:
///
///     alice:hunter2          plaintext password
///     bob:#<32 hex digits>   a precomputed NT hash
///     carol:hunter2:ro       read-only account
///
/// Passwords in a config string are as exposed as the file they live in; the
/// `#hash` form is there so a deployment can avoid writing them down twice, not
/// because a hash is meaningfully safer than the password it stands for.
pub fn UserTable(comptime max_users: usize, comptime max_name: usize) type {
    return struct {
        entries: [max_users]Entry = undefined,
        count: usize = 0,

        const Self = @This();

        const Entry = struct {
            name: [max_name]u8 = undefined,
            name_len: usize = 0,
            account: Account,

            fn name_(e: *const Entry) []const u8 {
                return e.name[0..e.name_len];
            }
        };

        pub const ParseError = error{ TooManyUsers, NameTooLong, BadHash, Empty } || unicode.Error;

        pub fn init(s: *Self) void {
            s.count = 0;
        }

        pub fn add(s: *Self, user: []const u8, password: []const u8, read_only: bool) ParseError!void {
            if (s.count == max_users) return error.TooManyUsers;
            if (user.len == 0 or user.len > max_name) return error.NameTooLong;
            const hash = if (password.len > 0 and password[0] == '#')
                try parseHash(password[1..])
            else
                try ntlm.ntHash(password);
            var entry: Entry = .{ .account = .{ .nt_hash = hash, .read_only = read_only, .uid = @intCast(s.count + 1) } };
            @memcpy(entry.name[0..user.len], user);
            entry.name_len = user.len;
            s.entries[s.count] = entry;
            s.count += 1;
        }

        pub fn parse(s: *Self, config: []const u8) ParseError!void {
            s.init();
            var it = std.mem.tokenizeAny(u8, config, ",\n\r");
            while (it.next()) |raw| {
                const line = std.mem.trim(u8, raw, " \t");
                if (line.len == 0 or line[0] == '#') continue;
                const first = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadHash;
                const rest = line[first + 1 ..];
                // The password may itself contain ':', so only a trailing
                // ":ro"/":rw" counts as the flag field.
                var password = rest;
                var read_only = false;
                if (std.mem.lastIndexOfScalar(u8, rest, ':')) |last| {
                    const tail = rest[last + 1 ..];
                    if (std.ascii.eqlIgnoreCase(tail, "ro") or std.ascii.eqlIgnoreCase(tail, "rw")) {
                        read_only = std.ascii.eqlIgnoreCase(tail, "ro");
                        password = rest[0..last];
                    }
                }
                try s.add(line[0..first], password, read_only);
            }
            if (s.count == 0) return error.Empty;
        }

        pub fn authenticator(s: *Self) Authenticator {
            return .{ .ctx = s, .vtable = &vtable };
        }

        const vtable: VTable = .{ .lookup = vLookup };

        fn vLookup(ctx: *anyopaque, user: []const u8, domain: []const u8) ?Account {
            _ = domain; // a standalone server: every account is local
            const s: *Self = @ptrCast(@alignCast(ctx));
            for (s.entries[0..s.count]) |*entry| {
                if (unicode.eqlIgnoreCase(entry.name_(), user)) return entry.account;
            }
            return null;
        }

        fn parseHash(hex: []const u8) ParseError![16]u8 {
            if (hex.len != 32) return error.BadHash;
            var out: [16]u8 = undefined;
            _ = std.fmt.hexToBytes(&out, hex) catch return error.BadHash;
            return out;
        }
    };
}

const testing = std.testing;
const Table = UserTable(8, 64);

test "parses accounts, passwords and the read-only flag" {
    var table: Table = undefined;
    try table.parse("alice:hunter2\nbob:s3cret:ro\n# a comment\n");

    const auth = table.authenticator();
    const alice = auth.lookup("alice", "").?;
    try testing.expectEqualSlices(u8, &(try ntlm.ntHash("hunter2")), &alice.nt_hash);
    try testing.expect(!alice.read_only);
    try testing.expect(auth.lookup("bob", "WORKGROUP").?.read_only);
}

test "user names match case-insensitively, unknown users do not match at all" {
    var table: Table = undefined;
    try table.parse("Alice:hunter2");
    const auth = table.authenticator();
    try testing.expect(auth.lookup("ALICE", "").?.uid == 1);
    try testing.expect(auth.lookup("alice", "") != null);
    try testing.expect(auth.lookup("mallory", "") == null);
    try testing.expect(auth.lookup("", "") == null); // never a null session
}

test "a precomputed NT hash is equivalent to the password" {
    var table: Table = undefined;
    try table.parse("alice:#8846f7eaee8fb117ad06bdd830b7586c");
    const auth = table.authenticator();
    try testing.expectEqualSlices(u8, &(try ntlm.ntHash("password")), &auth.lookup("alice", "").?.nt_hash);
}

test "passwords containing a colon survive parsing" {
    var table: Table = undefined;
    try table.parse("alice:a:b:c");
    const auth = table.authenticator();
    try testing.expectEqualSlices(u8, &(try ntlm.ntHash("a:b:c")), &auth.lookup("alice", "").?.nt_hash);

    try table.parse("bob:a:b:ro");
    try testing.expectEqualSlices(u8, &(try ntlm.ntHash("a:b")), &table.authenticator().lookup("bob", "").?.nt_hash);
}

test "malformed configuration is refused rather than half-applied" {
    var table: Table = undefined;
    try testing.expectError(error.BadHash, table.parse("no-colon-here"));
    try testing.expectError(error.Empty, table.parse("   \n# only comments\n"));
    try testing.expectError(error.BadHash, table.parse("alice:#nothex"));
}
