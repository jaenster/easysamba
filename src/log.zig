//! Line logging straight to stderr. No allocator, no buffering beyond one
//! stack line, and no `std.log` — a daemon whose logging path can fail or
//! allocate is a daemon that dies at the worst moment.

const std = @import("std");
const builtin = @import("builtin");

pub const Level = enum(u8) {
    err = 0,
    warn = 1,
    info = 2,
    debug = 3,

    fn tag(l: Level) []const u8 {
        return switch (l) {
            .err => "error",
            .warn => "warn",
            .info => "info",
            .debug => "debug",
        };
    }
};

/// Anything above this is dropped before it is formatted.
pub var level: Level = .info;

pub fn log(comptime l: Level, comptime fmt: []const u8, args: anytype) void {
    if (@intFromEnum(l) > @intFromEnum(level)) return;
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    w.print("[{s}] ", .{comptime l.tag()}) catch return;
    w.print(fmt, args) catch {};
    w.writeByte('\n') catch {
        // A line too long for the buffer still gets a terminator, so the next
        // one does not run into it.
        buf[buf.len - 1] = '\n';
        writeAll(&buf);
        return;
    };
    writeAll(w.buffered());
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    log(.err, fmt, args);
}
pub fn warn(comptime fmt: []const u8, args: anytype) void {
    log(.warn, fmt, args);
}
pub fn info(comptime fmt: []const u8, args: anytype) void {
    log(.info, fmt, args);
}
pub fn debug(comptime fmt: []const u8, args: anytype) void {
    log(.debug, fmt, args);
}

fn writeAll(bytes: []const u8) void {
    var written: usize = 0;
    while (written < bytes.len) {
        const rc: isize = if (builtin.os.tag == .linux)
            @bitCast(std.os.linux.write(2, bytes.ptr + written, bytes.len - written))
        else
            std.c.write(2, bytes.ptr + written, bytes.len - written);
        if (rc <= 0) return; // stderr is gone or full; dropping the line is the only option
        written += @intCast(rc);
    }
}
