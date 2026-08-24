//! The share adapter interface: everything the SMB layer is allowed to know
//! about what it is exporting.
//!
//! A share is a vtable and an opaque context, so an adapter can be a directory
//! on disk, a read-only view of a database, a tarball, an object store — the
//! protocol code never learns which. The rules an adapter may rely on:
//!
//!   * Paths arrive normalized: UTF-8, `/`-separated, no leading or trailing
//!     separator, no `.` or `..` component, no NUL. The share root is `""`.
//!     `smb/unicode.zig` guarantees this before any adapter is called.
//!   * Calls are made from one thread, in order, and never re-entered.
//!   * Nothing may allocate. Names are written into caller-owned buffers.
//!   * Every call must return promptly. This server multiplexes one thread over
//!     every connection, so an adapter that blocks for a second stalls the
//!     whole daemon for a second.
//!
//! `Error` is deliberately small and protocol-shaped: each variant maps to the
//! one NTSTATUS a client knows how to react to.

const std = @import("std");
const status = @import("../smb/status.zig");
const filetime = @import("../smb/time.zig");

pub const Error = error{
    NotFound,
    PathNotFound,
    Exists,
    AccessDenied,
    IsDirectory,
    NotDirectory,
    NotEmpty,
    NoSpace,
    TooManyOpen,
    NameTooLong,
    InvalidPath,
    Unsupported,
    Io,
};

pub fn statusFor(err: Error) status.Status {
    return switch (err) {
        error.NotFound => status.OBJECT_NAME_NOT_FOUND,
        error.PathNotFound => status.OBJECT_PATH_NOT_FOUND,
        error.Exists => status.OBJECT_NAME_COLLISION,
        error.AccessDenied => status.ACCESS_DENIED,
        error.IsDirectory => status.FILE_IS_A_DIRECTORY,
        error.NotDirectory => status.NOT_A_DIRECTORY,
        error.NotEmpty => status.DIRECTORY_NOT_EMPTY,
        error.NoSpace => status.DISK_FULL,
        error.TooManyOpen => status.TOO_MANY_OPENED_FILES,
        error.NameTooLong => status.OBJECT_NAME_INVALID,
        error.InvalidPath => status.OBJECT_PATH_SYNTAX_BAD,
        error.Unsupported => status.NOT_SUPPORTED,
        error.Io => status.UNSUCCESSFUL,
    };
}

/// Opaque to the SMB layer; an adapter puts an index or a pointer here.
pub const Handle = u64;

/// The FILE_ATTRIBUTE_* bits a file server has any business exposing.
pub const Attributes = packed struct(u32) {
    read_only: bool = false,
    hidden: bool = false,
    system: bool = false,
    _pad3: u1 = 0,
    directory: bool = false,
    archive: bool = false,
    _pad6: u1 = 0,
    normal: bool = false,
    _rest: u24 = 0,

    pub fn bits(a: Attributes) u32 {
        return @bitCast(a);
    }

    /// What goes on the wire when nothing else is set: Windows treats an
    /// all-zero attribute word as invalid.
    pub fn wire(a: Attributes) u32 {
        const raw = a.bits();
        return if (raw == 0) @as(u32, 0x80) else raw; // FILE_ATTRIBUTE_NORMAL
    }
};

pub const Meta = struct {
    size: u64 = 0,
    /// Bytes actually occupied. Adapters with no notion of allocation may
    /// report `size` rounded up, or `size` itself.
    alloc_size: u64 = 0,
    attributes: Attributes = .{},
    created: u64 = 0,
    accessed: u64 = 0,
    modified: u64 = 0,
    changed: u64 = 0,
    /// Stable per-object identity. Clients cache on it, so two different
    /// objects must never share one, and one object must keep its own across
    /// opens. Zero means "the adapter has no idea", which costs the client its
    /// cache but nothing else.
    file_id: u64 = 0,
    links: u32 = 1,

    pub fn isDir(m: Meta) bool {
        return m.attributes.directory;
    }
};

pub const Disposition = enum {
    /// Replace if it exists, create if it does not.
    supersede,
    /// Must exist.
    open,
    /// Must not exist.
    create,
    /// Open, creating when absent.
    open_if,
    /// Must exist; truncate it.
    overwrite,
    /// Truncate when present, create when absent.
    overwrite_if,
};

pub const OpenOptions = struct {
    read: bool = true,
    write: bool = false,
    /// Delete access was requested; the adapter may refuse early rather than at
    /// close time.
    delete: bool = false,
    disposition: Disposition = .open,
    /// `true` = must be a directory, `false` = must not be, `null` = either.
    directory: ?bool = null,
    /// Attributes to give a newly created object.
    attributes: Attributes = .{},
};

pub const Action = enum(u32) {
    superseded = 0,
    opened = 1,
    created = 2,
    overwritten = 3,
};

pub const Opened = struct {
    handle: Handle,
    action: Action,
    meta: Meta,
};

/// A directory listing position. The adapter owns both fields and may use them
/// however it likes; the server only stores the cursor between requests and
/// resets it to `.{}` when a client asks to restart the scan.
pub const Cursor = struct {
    index: u64 = 0,
    state: u64 = 0,
};

pub const DirEntry = struct {
    name: []const u8,
    meta: Meta,
};

/// Which timestamps and attributes a SET_INFO wants changed. A null field means
/// "leave it alone", which is how SMB2 expresses an unchanged timestamp.
pub const MetaChanges = struct {
    created: ?u64 = null,
    accessed: ?u64 = null,
    modified: ?u64 = null,
    changed: ?u64 = null,
    attributes: ?Attributes = null,
};

pub const FsInfo = struct {
    total_bytes: u64,
    free_bytes: u64,
    /// Reported as sectors-per-unit × bytes-per-sector; keep it a power of two.
    block_size: u32 = 4096,
    /// Volume label, UTF-8.
    label: []const u8 = "",
    serial: u32 = 0,
    /// Set when the adapter cannot write no matter who is asking.
    read_only: bool = false,
    case_sensitive: bool = false,
};

pub const VTable = struct {
    open: *const fn (ctx: *anyopaque, path: []const u8, opts: OpenOptions) Error!Opened,
    close: *const fn (ctx: *anyopaque, handle: Handle) void,
    stat: *const fn (ctx: *anyopaque, handle: Handle) Error!Meta,

    read: *const fn (ctx: *anyopaque, handle: Handle, offset: u64, buf: []u8) Error!usize,
    write: *const fn (ctx: *anyopaque, handle: Handle, offset: u64, data: []const u8) Error!usize,
    truncate: *const fn (ctx: *anyopaque, handle: Handle, size: u64) Error!void,
    flush: *const fn (ctx: *anyopaque, handle: Handle) Error!void,

    /// Writes the next entry's name into `name_buf` and fills `out`. Returns
    /// false at the end of the directory. An adapter must NOT emit `.` or `..`:
    /// the server prepends both to every listing itself, so that no adapter has
    /// to know clients insist on them.
    readDir: *const fn (ctx: *anyopaque, handle: Handle, cursor: *Cursor, name_buf: []u8, out: *DirEntry) Error!bool,

    setMeta: *const fn (ctx: *anyopaque, handle: Handle, changes: MetaChanges) Error!void,
    /// `replace` mirrors SMB2's ReplaceIfExists.
    rename: *const fn (ctx: *anyopaque, handle: Handle, new_path: []const u8, replace: bool) Error!void,
    /// Unlink whatever the handle refers to. Called at close time for a handle
    /// marked delete-on-close, so the object may still be open.
    remove: *const fn (ctx: *anyopaque, handle: Handle) Error!void,

    statFs: *const fn (ctx: *anyopaque) Error!FsInfo,
};

pub const Share = @This();

ctx: *anyopaque,
vtable: *const VTable,
/// The name clients connect to, as `\\server\<name>`. Compared case-insensitively.
name: []const u8,
comment: []const u8 = "",
/// Refuse every write regardless of what the adapter would allow. This is the
/// export-level switch; an adapter may be read-only on its own account too.
read_only: bool = false,

pub fn open(s: Share, path: []const u8, opts: OpenOptions) Error!Opened {
    if (s.read_only and (opts.write or opts.delete or opts.disposition != .open)) return error.AccessDenied;
    return s.vtable.open(s.ctx, path, opts);
}

pub fn close(s: Share, handle: Handle) void {
    s.vtable.close(s.ctx, handle);
}

pub fn stat(s: Share, handle: Handle) Error!Meta {
    return s.vtable.stat(s.ctx, handle);
}

pub fn read(s: Share, handle: Handle, offset: u64, buf: []u8) Error!usize {
    return s.vtable.read(s.ctx, handle, offset, buf);
}

pub fn write(s: Share, handle: Handle, offset: u64, data: []const u8) Error!usize {
    if (s.read_only) return error.AccessDenied;
    return s.vtable.write(s.ctx, handle, offset, data);
}

pub fn truncate(s: Share, handle: Handle, size: u64) Error!void {
    if (s.read_only) return error.AccessDenied;
    return s.vtable.truncate(s.ctx, handle, size);
}

pub fn flush(s: Share, handle: Handle) Error!void {
    return s.vtable.flush(s.ctx, handle);
}

pub fn readDir(s: Share, handle: Handle, cursor: *Cursor, name_buf: []u8, out: *DirEntry) Error!bool {
    return s.vtable.readDir(s.ctx, handle, cursor, name_buf, out);
}

pub fn setMeta(s: Share, handle: Handle, changes: MetaChanges) Error!void {
    if (s.read_only) return error.AccessDenied;
    return s.vtable.setMeta(s.ctx, handle, changes);
}

pub fn rename(s: Share, handle: Handle, new_path: []const u8, replace: bool) Error!void {
    if (s.read_only) return error.AccessDenied;
    return s.vtable.rename(s.ctx, handle, new_path, replace);
}

pub fn remove(s: Share, handle: Handle) Error!void {
    if (s.read_only) return error.AccessDenied;
    return s.vtable.remove(s.ctx, handle);
}

pub fn statFs(s: Share) Error!FsInfo {
    var info = try s.vtable.statFs(s.ctx);
    if (s.read_only) info.read_only = true;
    return info;
}

const testing = std.testing;

test "attribute bits match the FILE_ATTRIBUTE_* values on the wire" {
    try testing.expectEqual(@as(u32, 0x01), (Attributes{ .read_only = true }).bits());
    try testing.expectEqual(@as(u32, 0x02), (Attributes{ .hidden = true }).bits());
    try testing.expectEqual(@as(u32, 0x04), (Attributes{ .system = true }).bits());
    try testing.expectEqual(@as(u32, 0x10), (Attributes{ .directory = true }).bits());
    try testing.expectEqual(@as(u32, 0x20), (Attributes{ .archive = true }).bits());
    try testing.expectEqual(@as(u32, 0x80), (Attributes{ .normal = true }).bits());
}

test "an empty attribute set goes out as FILE_ATTRIBUTE_NORMAL" {
    try testing.expectEqual(@as(u32, 0x80), (Attributes{}).wire());
    try testing.expectEqual(@as(u32, 0x10), (Attributes{ .directory = true }).wire());
}

test "every adapter error has a distinct client-visible status" {
    const codes = [_]status.Status{
        statusFor(error.NotFound),    statusFor(error.PathNotFound),
        statusFor(error.Exists),      statusFor(error.AccessDenied),
        statusFor(error.IsDirectory), statusFor(error.NotDirectory),
        statusFor(error.NotEmpty),    statusFor(error.NoSpace),
    };
    for (codes, 0..) |a, i| {
        try testing.expect(status.isError(a));
        for (codes[i + 1 ..]) |b| try testing.expect(a != b);
    }
}
