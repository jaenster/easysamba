//! easysambad — the daemon.
//!
//! The whole server is one value in main's frame: no globals, no allocator, no
//! heap. Its size is a compile-time constant, printed at startup, so the memory
//! ceiling is known before the first client connects.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const easysamba = @import("easysamba");

const server = easysamba.server;
const log = easysamba.log;
const sys = easysamba.sys;

/// Sized for a small file server: a handful of clients, a handful of shares.
/// Everything below follows from `-Dmax-io` and `-Dconnections`.
///
/// The I/O size is the interesting one. It is what the server advertises as
/// MaxRead/MaxWrite, so it decides how many round trips a file takes. Measured
/// on loopback with a 200 MB file, warm: 64 KiB gives ~1.4 GB/s, 256 KiB and
/// above give ~2.2 GB/s, and the daemon's CPU time falls by a third across that
/// range. Past 256 KiB the gain is inside the noise while the memory per
/// connection keeps doubling, which is why that is the default and this is a
/// knob rather than a constant.
const io_bytes: u32 = build_options.max_io_kib * 1024;

const limits: server.Limits = .{
    .max_connections = build_options.max_connections,
    .sessions_per_connection = 4,
    .trees_per_session = 8,
    .opens_per_session = 64,
    .max_shares = 8,
    // Input holds one largest-possible write plus its header and a little
    // pipelining behind it; output holds one largest-possible read plus room to
    // start the next answer before the first has drained.
    .in_buffer = io_bytes + 128 * 1024,
    .out_buffer = 2 * io_bytes,
    .max_read = io_bytes,
    .max_write = io_bytes,
    .max_transact = io_bytes,
    .path_bytes = 512,
    .search_pattern_bytes = 128,
};

const Smbd = easysamba.Server(limits);
const Fs = easysamba.PosixFs(.{ .max_nodes = 256, .max_path = limits.path_bytes });
const Accounts = easysamba.UserTable(32, 64);

const max_shares = limits.max_shares;

const ShareSpec = struct {
    name: []const u8,
    path: []const u8,
    read_only: bool,
};

const Options = struct {
    bind: []const u8 = "",
    port: u16 = 445,
    netbios_name: []const u8 = "EASYSAMBA",
    domain: []const u8 = "WORKGROUP",
    require_signing: bool = false,
    log_level: log.Level = .info,
    shares: [max_shares]ShareSpec = undefined,
    share_count: usize = 0,
    /// Accounts given on the command line, in `user:password[:ro]` form.
    users: [1024]u8 = undefined,
    users_len: usize = 0,
    users_file: []const u8 = "",
};

/// Everything the daemon owns, in one value.
const Daemon = struct {
    smbd: Smbd,
    filesystems: [max_shares]Fs,
    accounts: Accounts,
};

pub fn main(init: std.process.Init.Minimal) !void {
    var options: Options = .{};
    parseArgs(&options, init.args) catch |err| {
        if (err == error.Help) {
            usage();
            return;
        }
        usage();
        return err;
    };
    log.level = options.log_level;

    if (options.share_count == 0) {
        log.err("no shares: pass at least one --share NAME=PATH", .{});
        return error.NoShares;
    }

    // ~20 MiB; build.zig raises the stack to fit it.
    var daemon: Daemon = undefined;

    try loadAccounts(&daemon.accounts, &options);
    daemon.smbd.init(.{
        .bind = options.bind,
        .port = options.port,
        .netbios_name = options.netbios_name,
        .domain = options.domain,
        .require_signing = options.require_signing,
    }, daemon.accounts.authenticator());

    for (options.shares[0..options.share_count], 0..) |spec, i| {
        daemon.filesystems[i].init(spec.path) catch |err| {
            log.err("share '{s}': cannot open '{s}': {s}", .{ spec.name, spec.path, @errorName(err) });
            return err;
        };
        var share = daemon.filesystems[i].share(spec.name);
        share.read_only = spec.read_only;
        try daemon.smbd.addShare(share);
        log.info("share \\\\{s}\\{s} -> {s}{s}", .{
            options.netbios_name,
            spec.name,
            spec.path,
            if (spec.read_only) " (read-only)" else "",
        });
    }
    defer for (daemon.filesystems[0..options.share_count]) |*fs| fs.deinit();

    daemon.smbd.listen() catch |err| {
        log.err("cannot listen on {s}:{d}: {s}{s}", .{
            if (options.bind.len == 0) "*" else options.bind,
            options.port,
            @errorName(err),
            if (options.port < 1024) " (ports below 1024 need root; try --port 4445)" else "",
        });
        return err;
    };
    defer daemon.smbd.deinit();

    log.info("easysambad listening on {s}:{d} ({s} backend, {d} connections max, {d} MiB resident)", .{
        if (options.bind.len == 0) "*" else options.bind,
        options.port,
        @tagName(easysamba.poller.backend),
        limits.max_connections,
        @sizeOf(Daemon) / (1024 * 1024),
    });

    try daemon.smbd.run();
}

fn parseArgs(options: *Options, args: std.process.Args) !void {
    var it = std.process.Args.Iterator.init(args);
    _ = it.next(); // argv[0]

    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return error.Help;
        if (std.mem.eql(u8, arg, "--require-signing")) {
            options.require_signing = true;
            continue;
        }
        const value = it.next() orelse {
            log.err("{s} needs a value", .{arg});
            return error.MissingValue;
        };
        if (std.mem.eql(u8, arg, "--bind")) {
            options.bind = value;
        } else if (std.mem.eql(u8, arg, "--port")) {
            options.port = std.fmt.parseInt(u16, value, 10) catch return error.BadPort;
        } else if (std.mem.eql(u8, arg, "--name")) {
            options.netbios_name = value;
        } else if (std.mem.eql(u8, arg, "--workgroup")) {
            options.domain = value;
        } else if (std.mem.eql(u8, arg, "--share")) {
            try addShare(options, value, false);
        } else if (std.mem.eql(u8, arg, "--share-ro")) {
            try addShare(options, value, true);
        } else if (std.mem.eql(u8, arg, "--user")) {
            try addUser(options, value);
        } else if (std.mem.eql(u8, arg, "--users")) {
            options.users_file = value;
        } else if (std.mem.eql(u8, arg, "--log")) {
            options.log_level = parseLevel(value) orelse return error.BadLogLevel;
        } else {
            log.err("unknown option '{s}'", .{arg});
            return error.UnknownOption;
        }
    }
}

fn addShare(options: *Options, spec: []const u8, read_only: bool) !void {
    if (options.share_count == max_shares) return error.TooManyShares;
    const equals = std.mem.indexOfScalar(u8, spec, '=') orelse {
        log.err("--share wants NAME=PATH, got '{s}'", .{spec});
        return error.BadShare;
    };
    var path = spec[equals + 1 ..];
    var ro = read_only;
    if (std.mem.endsWith(u8, path, ":ro")) {
        path = path[0 .. path.len - 3];
        ro = true;
    }
    if (equals == 0 or path.len == 0) return error.BadShare;
    options.shares[options.share_count] = .{
        .name = spec[0..equals],
        .path = path,
        .read_only = ro,
    };
    options.share_count += 1;
}

/// Accounts from argv are copied into the options value, because the account
/// table wants one config string and argv gives them one at a time.
fn addUser(options: *Options, spec: []const u8) !void {
    const needed = spec.len + 1;
    if (options.users_len + needed > options.users.len) return error.TooManyUsers;
    @memcpy(options.users[options.users_len..][0..spec.len], spec);
    options.users[options.users_len + spec.len] = '\n';
    options.users_len += needed;
}

fn loadAccounts(accounts: *Accounts, options: *Options) !void {
    if (options.users_file.len > 0) {
        const fd = sys.openat(sys.at_fdcwd, options.users_file, .{}, 0) catch |err| {
            log.err("cannot read '{s}': {s}", .{ options.users_file, @errorName(err) });
            return err;
        };
        defer sys.close(fd);
        var buf: [8192]u8 = undefined;
        var len: usize = 0;
        while (len < buf.len) {
            const n = try sys.pread(fd, buf[len..], len);
            if (n == 0) break;
            len += n;
        }
        accounts.parse(buf[0..len]) catch |err| {
            log.err("'{s}' is not a valid account file: {s}", .{ options.users_file, @errorName(err) });
            return err;
        };
        // The file has been turned into hashes; do not leave the passwords in
        // memory a moment longer than that took.
        std.crypto.secureZero(u8, &buf);
        return;
    }
    if (options.users_len == 0) {
        log.err("no accounts: pass --user NAME:PASSWORD or --users FILE", .{});
        return error.NoAccounts;
    }
    accounts.parse(options.users[0..options.users_len]) catch |err| {
        log.err("bad --user value: {s}", .{@errorName(err)});
        return err;
    };
    std.crypto.secureZero(u8, options.users[0..options.users_len]);
    options.users_len = 0;
}

fn parseLevel(text: []const u8) ?log.Level {
    if (std.mem.eql(u8, text, "error")) return .err;
    if (std.mem.eql(u8, text, "warn")) return .warn;
    if (std.mem.eql(u8, text, "info")) return .info;
    if (std.mem.eql(u8, text, "debug")) return .debug;
    return null;
}

fn usage() void {
    const text =
        \\easysambad — an SMB2 file server
        \\
        \\usage: easysambad --share NAME=PATH --user NAME:PASSWORD [options]
        \\
        \\shares
        \\  --share NAME=PATH        export PATH as \\server\NAME (repeatable)
        \\  --share-ro NAME=PATH     export it read-only (same as PATH:ro)
        \\
        \\accounts (there is no guest access; every client authenticates)
        \\  --user NAME:PASSWORD     add an account, :ro at the end for read-only
        \\  --users FILE             read accounts from a file, one per line;
        \\                           a password of #<32 hex> is an NT hash
        \\
        \\network
        \\  --bind ADDR              address to listen on (default: all)
        \\  --port N                 port (default 445; below 1024 needs root)
        \\  --name NAME              NetBIOS server name (default EASYSAMBA)
        \\  --workgroup NAME         workgroup (default WORKGROUP)
        \\  --require-signing        refuse clients that will not sign
        \\
        \\  --log LEVEL              error, warn, info (default) or debug
        \\  --help
        \\
        \\example
        \\  easysambad --port 4445 --share files=/srv/files --user alice:hunter2
        \\
    ;
    write(text);
}

fn write(bytes: []const u8) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.write(2, bytes.ptr, bytes.len);
    } else {
        _ = std.c.write(2, bytes.ptr, bytes.len);
    }
}
