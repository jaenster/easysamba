//! Throughput benchmark for the SMB2 dispatch path.
//!
//! Runs the real server against a real share with the real wire format, but
//! without a socket: `LoopbackClient` hands each request straight to
//! `handleFrame`. What that measures is the part this project can actually make
//! faster — parsing, dispatch, the adapter call, response building and signing
//! — with no kernel scheduling noise on top of it.
//!
//!     zig build bench -Doptimize=ReleaseFast
//!
//! Numbers from a Debug build are meaningless; the runner says so if you do it.

const std = @import("std");
const builtin = @import("builtin");
const easysamba = @import("easysamba");

const server_mod = easysamba.server;
const status = easysamba.status;
const info = easysamba.info;
const sys = easysamba.sys;

const limits: server_mod.Limits = .{
    .max_connections = 1,
    .sessions_per_connection = 2,
    .trees_per_session = 4,
    .opens_per_session = 16,
    .max_shares = 2,
    .in_buffer = 2 * 1024 * 1024,
    .out_buffer = 2 * 1024 * 1024,
    .max_read = 1024 * 1024,
    .max_write = 1024 * 1024,
    .max_transact = 1024 * 1024,
    .path_bytes = 256,
    .search_pattern_bytes = 64,
};

const Bench = easysamba.Server(limits);
const Client = easysamba.LoopbackClient(Bench);
const MemFs = easysamba.MemFs(.{ .max_nodes = 64, .max_file_bytes = 1024 * 1024, .max_path = 128 });
const PosixFs = easysamba.PosixFs(.{ .max_nodes = 64, .max_path = 256 });
const Accounts = easysamba.UserTable(2, 32);

const password = "hunter2";
const scratch_bytes = 4 * 1024 * 1024;

/// Everything the benchmark owns, in one value — the same shape the daemon uses.
const World = struct {
    server: Bench,
    memfs: MemFs,
    posixfs: PosixFs,
    accounts: Accounts,
    scratch: [scratch_bytes]u8,
};

var world: World = undefined;

pub fn main() !void {
    if (builtin.mode == .Debug) {
        print("warning: Debug build; run `zig build bench -Doptimize=ReleaseFast` for real numbers\n\n", .{});
    }

    try run(.memfs);
    print("\n", .{});
    try run(.posixfs);
}

const Backend = enum { memfs, posixfs };

fn run(backend: Backend) !void {
    try world.accounts.parse("alice:" ++ password);
    world.server.init(.{ .netbios_name = "BENCH" }, world.accounts.authenticator());

    var scratch_path: [256]u8 = undefined;
    switch (backend) {
        .memfs => {
            world.memfs.init();
            try world.memfs.put("small.bin", &[_]u8{0xAB} ** 4096);
            try world.memfs.put("large.bin", &[_]u8{0xCD} ** (1024 * 1024));
            var i: usize = 0;
            while (i < 32) : (i += 1) {
                const name = try std.fmt.bufPrint(&scratch_path, "dir/entry-{d:0>3}.txt", .{i});
                try world.memfs.put(name, "x");
            }
            try world.server.addShare(world.memfs.share("data"));
        },
        .posixfs => {
            const root = "/tmp/easysamba-bench";
            sys.mkdirat(sys.at_fdcwd, root, 0o755) catch {};
            try world.posixfs.init(root);
            const share = world.posixfs.share("data");
            try seed(share, "small.bin", 4096);
            try seed(share, "large.bin", 1024 * 1024);
            var i: usize = 0;
            while (i < 32) : (i += 1) {
                const name = try std.fmt.bufPrint(&scratch_path, "entry-{d:0>3}.txt", .{i});
                try seed(share, name, 1);
            }
            try world.server.addShare(share);
        },
    }

    var client = Client.init(&world.server, 0, &world.scratch);
    _ = client.negotiate();
    if (client.login("alice", password, .raw, false) != status.SUCCESS) return error.LoginFailed;
    if (client.treeConnect("data") != status.SUCCESS) return error.TreeConnectFailed;

    print("{s} share\n", .{@tagName(backend)});
    print("  {s:<34} {s:>12} {s:>14}\n", .{ "operation", "ops/sec", "throughput" });

    try benchEcho(&client);
    try benchOpenClose(&client);
    try benchCompound(&client);
    try benchQueryInfo(&client);
    try benchReadDir(&client, backend);
    try benchRead(&client, "small.bin", 4 * 1024);
    try benchRead(&client, "large.bin", 64 * 1024);
    try benchRead(&client, "large.bin", 512 * 1024);
    try benchWrite(&client, 64 * 1024);
    try benchPipelined(&client, .echo, 64);
    try benchPipelined(&client, .read, 32);
    try benchSignedRead(64 * 1024);

    if (backend == .posixfs) world.posixfs.deinit();
}

fn seed(share: easysamba.Share, path: []const u8, size: usize) !void {
    const opened = try share.open(path, .{ .write = true, .disposition = .overwrite_if });
    defer share.close(opened.handle);
    var chunk: [64 * 1024]u8 = @splat(0xEF);
    var written: usize = 0;
    while (written < size) {
        const n = @min(chunk.len, size - written);
        written += try share.write(opened.handle, written, chunk[0..n]);
    }
    try share.truncate(opened.handle, size);
}

// ---------------------------------------------------------------- cases

fn benchEcho(client: *Client) !void {
    var timer = Timer.start("echo (dispatch floor)");
    while (timer.next()) {
        const response = client.echo();
        if (loopbackStatus(response) != status.SUCCESS) return error.EchoFailed;
    }
    timer.report(0);
}

fn benchOpenClose(client: *Client) !void {
    var timer = Timer.start("create + close");
    while (timer.next()) {
        if (client.open(.{ .path = "small.bin" }) != status.SUCCESS) return error.OpenFailed;
        _ = client.closeFile();
    }
    timer.report(0);
}

/// What macOS actually does to stat a file: one frame, three requests.
fn benchCompound(client: *Client) !void {
    const wire = easysamba.wire;
    const hdr = easysamba.header;

    var frame: [1024]u8 = undefined;
    var w = wire.Writer.init(&frame);
    var create_body: [512]u8 = undefined;
    const create = Client.createBody(.{ .path = "small.bin" }, &create_body);

    const first = w.pos;
    try hdr.write(&w, .{ .command = .create, .credits = 64, .message_id = 1, .session_id = client.session_id, .tree_id = client.tree_id });
    try w.blob(create);
    try w.alignTo(8);
    try w.patchInt(u32, first + 20, @intCast(w.pos - first));

    const second = w.pos;
    try hdr.write(&w, .{ .command = .query_info, .credits = 64, .flags = hdr.flags.RELATED_OPERATIONS, .message_id = 2 });
    try w.u16_(41);
    try w.u8_(@intFromEnum(info.InfoType.file));
    try w.u8_(@intFromEnum(info.FileClass.all));
    try w.u32_(4096);
    try w.u16_(0);
    try w.u16_(0);
    try w.u32_(0);
    try w.u32_(0);
    try w.u32_(0);
    try w.blob(&([_]u8{0xFF} ** 16));
    try w.alignTo(8);
    try w.patchInt(u32, second + 20, @intCast(w.pos - second));

    try hdr.write(&w, .{ .command = .close, .credits = 64, .flags = hdr.flags.RELATED_OPERATIONS, .message_id = 3 });
    try w.u16_(24);
    try w.u16_(0);
    try w.u32_(0);
    try w.blob(&([_]u8{0xFF} ** 16));
    const message = w.written();

    var timer = Timer.start("create+query_info+close (1 frame)");
    while (timer.next()) {
        const responses = client.sendFrame(message);
        if (loopbackStatus(responses) != status.SUCCESS) return error.CompoundFailed;
    }
    timer.report(0);
}

fn benchQueryInfo(client: *Client) !void {
    if (client.open(.{ .path = "small.bin" }) != status.SUCCESS) return error.OpenFailed;
    defer _ = client.closeFile();

    var timer = Timer.start("query_info (FileAllInformation)");
    while (timer.next()) {
        const response = client.queryInfo(.file, @intFromEnum(info.FileClass.all));
        if (loopbackStatus(response) != status.SUCCESS) return error.QueryFailed;
    }
    timer.report(0);
}

fn benchReadDir(client: *Client, backend: Backend) !void {
    const path = if (backend == .memfs) "dir" else "";
    var timer = Timer.start("query_directory (34 entries)");
    while (timer.next()) {
        if (client.open(.{ .path = path, .options = 1 }) != status.SUCCESS) return error.OpenFailed;
        while (loopbackStatus(client.queryDirectory(.id_both_directory, "*", 0)) == status.SUCCESS) {}
        _ = client.closeFile();
    }
    timer.report(0);
}

fn benchRead(client: *Client, path: []const u8, length: u32) !void {
    if (client.open(.{ .path = path }) != status.SUCCESS) return error.OpenFailed;
    defer _ = client.closeFile();

    var label: [64]u8 = undefined;
    var timer = Timer.start(std.fmt.bufPrint(&label, "read {s}", .{humanSize(length)}) catch unreachable);
    while (timer.next()) {
        const response = client.readFile(0, length);
        if (loopbackStatus(response) != status.SUCCESS) return error.ReadFailed;
    }
    timer.report(length);
}

fn benchWrite(client: *Client, length: u32) !void {
    if (client.open(.{ .path = "scratch.bin", .access_mask = 0x0012_0116, .disposition = 5 }) != status.SUCCESS) {
        return error.OpenFailed;
    }
    defer _ = client.closeFile();

    const data = world.scratch[world.scratch.len - length ..];
    @memset(data, 0x5A);

    var label: [64]u8 = undefined;
    var timer = Timer.start(std.fmt.bufPrint(&label, "write {s}", .{humanSize(length)}) catch unreachable);
    while (timer.next()) {
        const response = client.writeFile(0, data);
        if (loopbackStatus(response) != status.SUCCESS) return error.WriteFailed;
    }
    timer.report(length);
}

/// Stands in for a socket that took everything offered.
fn drain(client: *Client) void {
    client.conn.out_len = 0;
    client.conn.out_sent = 0;
}

/// Requests through the connection buffers instead of straight into the
/// dispatcher. Transport framing, the input cursor, and the pause-and-resume of
/// a full output buffer are all on this path and none of them are on
/// `handleFrame`'s, so this is the part a pipelining client actually pays for.
fn benchPipelined(client: *Client, comptime kind: enum { echo, read }, depth: usize) !void {
    const length: u32 = 64 * 1024;
    if (kind == .read) {
        if (client.open(.{ .path = "large.bin" }) != status.SUCCESS) return error.OpenFailed;
    }
    defer if (kind == .read) {
        _ = client.closeFile();
    };

    // One batch, built once: what is being measured is the server's side of a
    // pipeline, not the cost of assembling one.
    var batch: [256 * 1024]u8 = undefined;
    var used: usize = 0;
    var i: usize = 0;
    while (i < depth) : (i += 1) {
        var body: [64]u8 = undefined;
        used += switch (kind) {
            .echo => client.buildFrame(.echo, &.{ 4, 0, 0, 0 }, batch[used..]),
            .read => client.buildFrame(.read, client.readBody(0, length, &body), batch[used..]),
        };
    }

    var label: [64]u8 = undefined;
    const name = switch (kind) {
        .echo => std.fmt.bufPrint(&label, "echo, {d} pipelined", .{depth}),
        .read => std.fmt.bufPrint(&label, "read 64 KiB, {d} pipelined", .{depth}),
    } catch unreachable;

    var timer = Timer.start(name);
    while (timer.next()) {
        drain(client);
        var fed: usize = 0;
        while (fed < used) {
            const accepted = client.server.feed(client.conn, batch[fed..used]);
            if (accepted == 0) return error.Stalled;
            fed += accepted;
            drain(client);
        }
        // Whatever a full output buffer left unanswered, answered now — the
        // resume a writable socket would have caused.
        while (client.conn.inPending() > 0) {
            _ = client.server.feed(client.conn, &.{});
            drain(client);
        }
    }
    timer.scale(depth);
    timer.report(if (kind == .read) length else 0);
}

/// The same read with HMAC-SHA256 over every request and response, which is
/// what a Windows 11 client asks for by default.
fn benchSignedRead(length: u32) !void {
    var signed = Client.init(&world.server, 0, &world.scratch);
    _ = signed.negotiate();
    if (signed.login("alice", password, .raw, true) != status.SUCCESS) return error.LoginFailed;
    if (signed.treeConnect("data") != status.SUCCESS) return error.TreeConnectFailed;
    if (signed.open(.{ .path = "large.bin" }) != status.SUCCESS) return error.OpenFailed;

    var label: [64]u8 = undefined;
    var timer = Timer.start(std.fmt.bufPrint(&label, "read {s}, signed", .{humanSize(length)}) catch unreachable);
    while (timer.next()) {
        const response = signed.readFile(0, length);
        if (loopbackStatus(response) != status.SUCCESS) return error.ReadFailed;
    }
    timer.report(length);
    _ = signed.closeFile();
}

// --------------------------------------------------------------- plumbing

fn loopbackStatus(response: []const u8) u32 {
    return std.mem.readInt(u32, response[8..12], .little);
}

/// Runs a case for a fixed wall-clock budget rather than a fixed iteration
/// count, so a slow operation does not stretch the run and a fast one still
/// gets enough samples to mean something.
const Timer = struct {
    label: []const u8,
    started: i128,
    deadline: i128,
    iterations: u64 = 0,
    warmup: u64 = 32,

    const budget_ns: i128 = 300 * std.time.ns_per_ms;

    fn start(label: []const u8) Timer {
        var t: Timer = .{ .label = label, .started = 0, .deadline = 0 };
        t.started = nowNs();
        t.deadline = t.started + budget_ns;
        return t;
    }

    fn next(t: *Timer) bool {
        t.iterations += 1;
        if (t.iterations <= t.warmup) return true;
        // Checking the clock every iteration would show up in the numbers for
        // the cheapest cases, so only every 64th.
        if (t.iterations % 64 != 0) return true;
        if (nowNs() < t.deadline) return true;
        t.iterations -= 1;
        return false;
    }

    /// One iteration answered `factor` requests, not one.
    fn scale(t: *Timer, factor: usize) void {
        t.iterations = t.warmup + (t.iterations - t.warmup) * factor;
    }

    fn report(t: *Timer, bytes_per_op: u64) void {
        const elapsed: f64 = @floatFromInt(nowNs() - t.started);
        const ops: f64 = @floatFromInt(t.iterations - t.warmup);
        const per_second = ops / (elapsed / std.time.ns_per_s);

        if (bytes_per_op == 0) {
            print("  {s:<34} {d:>12.0} {s:>14}\n", .{ t.label, per_second, "-" });
        } else {
            const mb = per_second * @as(f64, @floatFromInt(bytes_per_op)) / (1024 * 1024);
            var buf: [32]u8 = undefined;
            const rate = std.fmt.bufPrint(&buf, "{d:.0} MiB/s", .{mb}) catch "?";
            print("  {s:<34} {d:>12.0} {s:>14}\n", .{ t.label, per_second, rate });
        }
    }
};

fn nowNs() i128 {
    var ts: std.c.timespec = undefined;
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.clock_gettime(.MONOTONIC, @ptrCast(&ts));
    } else {
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
    }
    return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
}

fn humanSize(bytes: u64) []const u8 {
    return switch (bytes) {
        4 * 1024 => "4 KiB",
        64 * 1024 => "64 KiB",
        512 * 1024 => "512 KiB",
        1024 * 1024 => "1 MiB",
        else => "?",
    };
}

fn print(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    w.print(fmt, args) catch return;
    const bytes = w.buffered();
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.write(1, bytes.ptr, bytes.len);
    } else {
        _ = std.c.write(1, bytes.ptr, bytes.len);
    }
}
