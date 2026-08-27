//! The information classes: the fixed record layouts SMB2 uses to answer
//! QUERY_DIRECTORY, QUERY_INFO and FS-info requests, and to carry a SET_INFO.
//!
//! Every layout here is byte-exact from MS-FSCC. Clients do not parse these
//! defensively — a field at the wrong offset does not produce an error, it
//! produces a file with the wrong size or a directory that appears empty, so
//! the tests below assert offsets rather than round-trips.

const std = @import("std");
const wire = @import("wire.zig");
const unicode = @import("unicode.zig");
const Share = @import("../vfs/Share.zig");

pub const Error = wire.Error || unicode.Error;

pub const InfoType = enum(u8) {
    file = 0x01,
    filesystem = 0x02,
    security = 0x03,
    quota = 0x04,
    _,
};

pub const FileClass = enum(u8) {
    directory = 1,
    full_directory = 2,
    both_directory = 3,
    basic = 4,
    standard = 5,
    internal = 6,
    ea = 7,
    access = 8,
    name = 9,
    rename = 10,
    names = 12,
    disposition = 13,
    position = 14,
    mode = 16,
    alignment = 17,
    all = 18,
    allocation = 19,
    end_of_file = 20,
    stream = 22,
    network_open = 34,
    attribute_tag = 35,
    id_both_directory = 37,
    id_full_directory = 38,
    _,
};

pub const FsClass = enum(u8) {
    volume = 1,
    size = 3,
    device = 4,
    attribute = 5,
    control = 6,
    full_size = 7,
    object_id = 8,
    sector_size = 11,
    _,
};

/// FILE_DEVICE_DISK / FILE_DEVICE_IS_MOUNTED.
const device_type_disk: u32 = 0x07;
const device_characteristics: u32 = 0x0000_0020;

const fs_attributes: u32 =
    0x0000_0002 | // CASE_PRESERVED_NAMES
    0x0000_0008 | // UNICODE_ON_DISK
    0x0000_0040; // PERSISTENT_ACLS is off; sparse/compression are off too

pub const max_component_name: u32 = 255;

// ---------------------------------------------------------------- directories

/// Writes one directory entry. `w` must be a cursor over the response's
/// output-buffer area alone, because NextEntryOffset and the 8-byte alignment
/// are both measured from the start of that area.
///
/// Returns false without writing anything when the entry does not fit, which is
/// how the caller learns to stop and let the client ask again.
pub fn writeDirEntry(
    w: *wire.Writer,
    class: FileClass,
    index: u32,
    entry: Share.DirEntry,
    is_last: bool,
) Error!bool {
    const start = w.pos;
    const name_len = try unicode.utf16leLen(entry.name);
    const fixed: usize = switch (class) {
        .directory => 64,
        .full_directory => 68,
        .id_full_directory => 80,
        .both_directory => 94,
        .id_both_directory => 104,
        .names => 12,
        else => return error.BadEncoding,
    };
    // The record must still be 8-byte alignable inside the buffer.
    const needed = std.mem.alignForward(usize, fixed + name_len, 8);
    if (w.space() < needed) return false;

    const m = entry.meta;
    try w.u32_(0); // NextEntryOffset, patched below
    try w.u32_(index);
    if (class != .names) {
        try w.u64_(m.created);
        try w.u64_(m.accessed);
        try w.u64_(m.modified);
        try w.u64_(m.changed);
        try w.u64_(m.size);
        try w.u64_(m.alloc_size);
        try w.u32_(m.attributes.wire());
    }
    try w.u32_(@intCast(name_len));
    switch (class) {
        .directory, .names => {},
        .full_directory => try w.u32_(0), // EaSize
        .id_full_directory => {
            try w.u32_(0); // EaSize
            try w.u32_(0); // Reserved
            try w.u64_(m.file_id);
        },
        .both_directory => {
            try w.u32_(0); // EaSize
            try w.u8_(0); // ShortNameLength: no 8.3 alias is offered
            try w.u8_(0); // Reserved
            try w.zeroes(24); // ShortName
        },
        .id_both_directory => {
            try w.u32_(0); // EaSize
            try w.u8_(0);
            try w.u8_(0);
            try w.zeroes(24);
            try w.u16_(0); // Reserved2
            try w.u64_(m.file_id);
        },
        else => unreachable,
    }
    std.debug.assert(w.pos - start == fixed);
    _ = try unicode.toUtf16le(try w.reserve(name_len), entry.name);
    try w.alignTo(8);

    if (!is_last) try w.patchInt(u32, start, @intCast(w.pos - start));
    return true;
}

// --------------------------------------------------------------- file info

/// What the server knows about an open handle that the file itself does not
/// say: the name it was opened by, and the few things a client can set on a
/// handle and expects to read back unchanged.
pub const HandleState = struct {
    /// The share-relative path in Windows form.
    name: []const u8 = "",
    delete_pending: bool = false,
    /// Where the client last put the handle. Nothing here reads or writes at
    /// it — every SMB2 read and write carries its own offset — but a client
    /// that sets it expects to find it again.
    position: u64 = 0,
    /// FileModeInformation, kept as the client set it.
    mode: u32 = 0,
    /// What this handle was actually granted, which is not always everything.
    access: u32 = full_access,
};

pub fn writeFileInfo(
    w: *wire.Writer,
    class: FileClass,
    meta: Share.Meta,
    state: HandleState,
) Error!void {
    const name = state.name;
    const delete_pending = state.delete_pending;
    switch (class) {
        .basic => try writeBasic(w, meta),
        .standard => try writeStandard(w, meta, delete_pending),
        .internal => try w.u64_(meta.file_id),
        .ea => try w.u32_(0),
        .access => try w.u32_(state.access),
        .position => try w.u64_(state.position),
        .mode => try w.u32_(state.mode),
        .alignment => try w.u32_(0), // FILE_BYTE_ALIGNMENT
        .name => {
            const len = try unicode.utf16leLen(name);
            try w.u32_(@intCast(len));
            _ = try unicode.toUtf16le(try w.reserve(len), name);
        },
        .network_open => {
            try w.u64_(meta.created);
            try w.u64_(meta.accessed);
            try w.u64_(meta.modified);
            try w.u64_(meta.changed);
            try w.u64_(meta.alloc_size);
            try w.u64_(meta.size);
            try w.u32_(meta.attributes.wire());
            try w.u32_(0); // Reserved
        },
        .attribute_tag => {
            try w.u32_(meta.attributes.wire());
            try w.u32_(0); // ReparseTag: nothing here is a reparse point
        },
        .stream => {
            if (meta.isDir()) return; // a directory has no data stream
            const stream_name = "::$DATA";
            const len = try unicode.utf16leLen(stream_name);
            try w.u32_(0); // NextEntryOffset: the only stream
            try w.u32_(@intCast(len));
            try w.u64_(meta.size);
            try w.u64_(meta.alloc_size);
            _ = try unicode.toUtf16le(try w.reserve(len), stream_name);
        },
        .all => {
            try writeBasic(w, meta);
            try writeStandard(w, meta, delete_pending);
            try w.u64_(meta.file_id); // Internal
            try w.u32_(0); // Ea
            try w.u32_(state.access); // Access
            try w.u64_(state.position); // Position
            try w.u32_(state.mode); // Mode
            try w.u32_(0); // Alignment
            const len = try unicode.utf16leLen(name);
            try w.u32_(@intCast(len));
            _ = try unicode.toUtf16le(try w.reserve(len), name);
        },
        else => return error.BadEncoding,
    }
}

/// What a quota field says when there is no quota.
const no_quota: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Everything a handle can be granted.
pub const full_access: u32 = 0x001F_01FF; // FILE_ALL_ACCESS

fn writeBasic(w: *wire.Writer, meta: Share.Meta) Error!void {
    try w.u64_(meta.created);
    try w.u64_(meta.accessed);
    try w.u64_(meta.modified);
    try w.u64_(meta.changed);
    try w.u32_(meta.attributes.wire());
    try w.u32_(0); // Reserved
}

fn writeStandard(w: *wire.Writer, meta: Share.Meta, delete_pending: bool) Error!void {
    try w.u64_(meta.alloc_size);
    try w.u64_(meta.size);
    try w.u32_(meta.links);
    try w.u8_(@intFromBool(delete_pending));
    try w.u8_(@intFromBool(meta.isDir()));
    try w.u16_(0); // Reserved
}

// ----------------------------------------------------------- filesystem info

pub fn writeFsInfo(w: *wire.Writer, class: FsClass, info: Share.FsInfo) Error!void {
    const unit: u64 = @max(info.block_size, 512);
    const total_units = info.total_bytes / unit;
    const free_units = info.free_bytes / unit;

    switch (class) {
        .volume => {
            const len = try unicode.utf16leLen(info.label);
            try w.u64_(0); // VolumeCreationTime
            try w.u32_(info.serial);
            try w.u32_(@intCast(len));
            try w.u8_(0); // SupportsObjects
            try w.u8_(0); // Reserved
            _ = try unicode.toUtf16le(try w.reserve(len), info.label);
        },
        .size => {
            try w.u64_(total_units);
            try w.u64_(free_units);
            try w.u32_(@intCast(unit / 512));
            try w.u32_(512);
        },
        .full_size => {
            try w.u64_(total_units);
            try w.u64_(free_units); // caller-available
            try w.u64_(free_units); // actually available
            try w.u32_(@intCast(unit / 512));
            try w.u32_(512);
        },
        .control => {
            // Quotas are not tracked, and saying so is the answer: no
            // threshold, no limit, no filtering.
            try w.u64_(0); // FreeSpaceStartFiltering
            try w.u64_(0); // FreeSpaceThreshold
            try w.u64_(0); // FreeSpaceStopFiltering
            try w.u64_(no_quota); // DefaultQuotaThreshold
            try w.u64_(no_quota); // DefaultQuotaLimit
            try w.u32_(0); // FileSystemControlFlags
            try w.u32_(0); // Padding
        },
        .device => {
            try w.u32_(device_type_disk);
            try w.u32_(device_characteristics);
        },
        .attribute => {
            const name = "NTFS"; // clients gate features on this string
            const len = try unicode.utf16leLen(name);
            var attributes = fs_attributes;
            if (info.case_sensitive) attributes |= 0x0000_0001; // CASE_SENSITIVE_SEARCH
            if (info.read_only) attributes |= 0x0008_0000; // READ_ONLY_VOLUME
            try w.u32_(attributes);
            try w.u32_(max_component_name);
            try w.u32_(@intCast(len));
            _ = try unicode.toUtf16le(try w.reserve(len), name);
        },
        .sector_size => {
            const physical: u32 = @intCast(unit);
            try w.u32_(512); // LogicalBytesPerSector
            try w.u32_(physical); // PhysicalBytesPerSectorForAtomicity
            try w.u32_(physical); // ...ForPerformance
            try w.u32_(physical); // FileSystemEffectivePhysicalBytesPerSector
            try w.u32_(0x00000003); // aligned, no partition misalignment
            try w.u32_(0); // ByteOffsetForSectorAlignment
            try w.u32_(0); // ByteOffsetForPartitionAlignment
        },
        else => return error.BadEncoding,
    }
}

// ------------------------------------------------------------------ security

/// A self-relative SECURITY_DESCRIPTOR granting Everyone full control, owned by
/// BUILTIN\\Administrators.
///
/// This server does not model Windows ACLs — the adapter decides what may be
/// touched, and the account decides whether writes are allowed at all. But
/// macOS and Windows both ask for a descriptor while copying files and treat a
/// failure as "you may not read this", so the honest answer ("no ACL model
/// here") has to be spelled as a permissive descriptor rather than an error.
pub fn writeSecurityDescriptor(w: *wire.Writer, requested: u32, granted: u32) Error!void {
    const owner_sid = [_]u8{ 1, 2, 0, 0, 0, 0, 0, 5 } ++ // S-1-5-32-544
        [_]u8{ 0x20, 0, 0, 0 } ++ [_]u8{ 0x20, 0x02, 0, 0 };
    const everyone_sid = [_]u8{ 1, 1, 0, 0, 0, 0, 0, 1 } ++ [_]u8{ 0, 0, 0, 0 }; // S-1-1-0

    const want_owner = requested & 0x0000_0001 != 0;
    const want_group = requested & 0x0000_0002 != 0;
    const want_dacl = requested & 0x0000_0004 != 0;

    const header_len: usize = 20;
    const ace_len: usize = 8 + everyone_sid.len;
    const acl_len: usize = 8 + ace_len;

    var offset: usize = header_len;
    const owner_at: u32 = if (want_owner) blk: {
        defer offset += owner_sid.len;
        break :blk @intCast(offset);
    } else 0;
    const group_at: u32 = if (want_group) blk: {
        defer offset += owner_sid.len;
        break :blk @intCast(offset);
    } else 0;
    const dacl_at: u32 = if (want_dacl) @intCast(offset) else 0;

    var control: u16 = 0x8000; // SE_SELF_RELATIVE
    if (want_dacl) control |= 0x0004; // SE_DACL_PRESENT

    try w.u8_(1); // Revision
    try w.u8_(0); // Sbz1
    try w.u16_(control);
    try w.u32_(owner_at);
    try w.u32_(group_at);
    try w.u32_(0); // OffsetSacl: never present
    try w.u32_(dacl_at);

    if (want_owner) try w.blob(&owner_sid);
    if (want_group) try w.blob(&owner_sid);
    if (want_dacl) {
        try w.u8_(2); // AclRevision
        try w.u8_(0); // Sbz1
        try w.u16_(@intCast(acl_len));
        try w.u16_(1); // AceCount
        try w.u16_(0); // Sbz2
        try w.u8_(0); // ACCESS_ALLOWED_ACE_TYPE
        try w.u8_(0x03); // OBJECT_INHERIT | CONTAINER_INHERIT
        try w.u16_(@intCast(ace_len));
        try w.u32_(granted);
        try w.blob(&everyone_sid);
    }
}

// -------------------------------------------------------------- set-info

pub const Rename = struct {
    replace: bool,
    /// Still in wire form (UTF-16LE, backslashes): the caller normalizes it.
    name_utf16: []const u8,
};

pub fn parseRename(buf: []const u8) Error!Rename {
    var r = wire.Reader.init(buf);
    const replace = try r.u8_();
    try r.skip(7); // Reserved
    _ = try r.u64_(); // RootDirectory: only 0 is meaningful over SMB2
    const len = try r.u32_();
    return .{ .replace = replace != 0, .name_utf16 = try r.take(len) };
}

pub fn parseDisposition(buf: []const u8) Error!bool {
    var r = wire.Reader.init(buf);
    return (try r.u8_()) != 0;
}

pub fn parseEndOfFile(buf: []const u8) Error!u64 {
    var r = wire.Reader.init(buf);
    return r.u64_();
}

pub fn parsePosition(buf: []const u8) Error!u64 {
    var r = wire.Reader.init(buf);
    return r.u64_();
}

pub fn parseMode(buf: []const u8) Error!u32 {
    var r = wire.Reader.init(buf);
    return r.u32_();
}

/// FileBasicInformation as a SET_INFO: a zero timestamp means "leave it", and
/// 0xFFFF... means "stop updating it", which we treat the same way — this
/// server never updates a timestamp behind the adapter's back.
pub fn parseBasic(buf: []const u8) Error!Share.MetaChanges {
    var r = wire.Reader.init(buf);
    var changes: Share.MetaChanges = .{};
    changes.created = optionalTime(try r.u64_());
    changes.accessed = optionalTime(try r.u64_());
    changes.modified = optionalTime(try r.u64_());
    changes.changed = optionalTime(try r.u64_());
    const attributes = try r.u32_();
    if (attributes != 0) changes.attributes = @bitCast(attributes);
    return changes;
}

fn optionalTime(value: u64) ?u64 {
    return switch (value) {
        0, std.math.maxInt(u64) => null,
        else => value,
    };
}

const testing = std.testing;

fn sampleMeta() Share.Meta {
    return .{
        .size = 0x1122334455667788,
        .alloc_size = 0x0000000000001000,
        .attributes = .{ .archive = true },
        .created = 1,
        .accessed = 2,
        .modified = 3,
        .changed = 4,
        .file_id = 0xABCDEF,
        .links = 1,
    };
}

test "FileIdBothDirectoryInformation matches the MS-FSCC layout" {
    var buf: [256]u8 = undefined;
    var w = wire.Writer.init(&buf);
    const entry: Share.DirEntry = .{ .name = "ab", .meta = sampleMeta() };
    try testing.expect(try writeDirEntry(&w, .id_both_directory, 7, entry, true));

    const out = w.written();
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, out[0..4], .little)); // last entry
    try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, out[4..8], .little)); // FileIndex
    try testing.expectEqual(@as(u64, 3), std.mem.readInt(u64, out[24..32], .little)); // LastWrite
    try testing.expectEqual(@as(u64, 0x1122334455667788), std.mem.readInt(u64, out[40..48], .little)); // EndOfFile
    try testing.expectEqual(@as(u32, 0x20), std.mem.readInt(u32, out[56..60], .little)); // attributes
    try testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, out[60..64], .little)); // FileNameLength
    try testing.expectEqual(@as(u8, 0), out[69]); // ShortNameLength
    try testing.expectEqual(@as(u64, 0xABCDEF), std.mem.readInt(u64, out[96..104], .little)); // FileId
    try testing.expectEqualSlices(u8, &.{ 'a', 0, 'b', 0 }, out[104..108]);
    try testing.expectEqual(@as(usize, 112), out.len); // padded to 8
}

test "chained directory entries point at each other and the last points nowhere" {
    var buf: [512]u8 = undefined;
    var w = wire.Writer.init(&buf);
    const a: Share.DirEntry = .{ .name = "first", .meta = sampleMeta() };
    const b: Share.DirEntry = .{ .name = "second-name", .meta = sampleMeta() };
    try testing.expect(try writeDirEntry(&w, .both_directory, 0, a, false));
    const second_at = w.pos;
    try testing.expect(try writeDirEntry(&w, .both_directory, 1, b, true));

    const out = w.written();
    const next = std.mem.readInt(u32, out[0..4], .little);
    try testing.expectEqual(second_at, next);
    try testing.expectEqual(@as(usize, 0), next % 8);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, out[second_at..][0..4], .little));
}

test "a directory entry that does not fit is refused without writing" {
    var buf: [70]u8 = undefined;
    var w = wire.Writer.init(&buf);
    const entry: Share.DirEntry = .{ .name = "too-long-for-this-buffer", .meta = sampleMeta() };
    try testing.expect(!try writeDirEntry(&w, .id_both_directory, 0, entry, true));
    try testing.expectEqual(@as(usize, 0), w.pos);
}

test "the fixed-size file info classes are exactly the documented sizes" {
    const cases = [_]struct { class: FileClass, size: usize }{
        .{ .class = .basic, .size = 40 },
        .{ .class = .standard, .size = 24 },
        .{ .class = .internal, .size = 8 },
        .{ .class = .ea, .size = 4 },
        .{ .class = .access, .size = 4 },
        .{ .class = .position, .size = 8 },
        .{ .class = .mode, .size = 4 },
        .{ .class = .alignment, .size = 4 },
        .{ .class = .network_open, .size = 56 },
        .{ .class = .attribute_tag, .size = 8 },
    };
    for (cases) |case| {
        var buf: [128]u8 = undefined;
        var w = wire.Writer.init(&buf);
        try writeFileInfo(&w, case.class, sampleMeta(), .{ .name = "name.txt" });
        try testing.expectEqual(case.size, w.pos);
    }
}

test "FileAllInformation is the concatenation clients expect" {
    var buf: [256]u8 = undefined;
    var w = wire.Writer.init(&buf);
    try writeFileInfo(&w, .all, sampleMeta(), .{ .name = "ab" });
    const out = w.written();
    // Basic(40) + Standard(24) + Internal(8) + Ea(4) + Access(4) + Position(8)
    // + Mode(4) + Alignment(4) = 96, then the name.
    try testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, out[96..100], .little));
    try testing.expectEqualSlices(u8, &.{ 'a', 0, 'b', 0 }, out[100..104]);
    try testing.expectEqual(@as(u64, 0x1000), std.mem.readInt(u64, out[40..48], .little)); // AllocationSize
    try testing.expectEqual(@as(u8, 0), out[68]); // DeletePending
}

test "standard info reports a directory and a pending delete" {
    var buf: [64]u8 = undefined;
    var w = wire.Writer.init(&buf);
    var meta = sampleMeta();
    meta.attributes = .{ .directory = true };
    try writeFileInfo(&w, .standard, meta, .{ .delete_pending = true });
    const out = w.written();
    try testing.expectEqual(@as(u8, 1), out[20]); // DeletePending
    try testing.expectEqual(@as(u8, 1), out[21]); // Directory
}

test "filesystem size classes convert bytes to allocation units" {
    var buf: [128]u8 = undefined;
    var w = wire.Writer.init(&buf);
    const info: Share.FsInfo = .{ .total_bytes = 4096 * 100, .free_bytes = 4096 * 40, .block_size = 4096 };
    try writeFsInfo(&w, .size, info);
    const out = w.written();
    try testing.expectEqual(@as(u64, 100), std.mem.readInt(u64, out[0..8], .little));
    try testing.expectEqual(@as(u64, 40), std.mem.readInt(u64, out[8..16], .little));
    try testing.expectEqual(@as(u32, 8), std.mem.readInt(u32, out[16..20], .little)); // sectors per unit
    try testing.expectEqual(@as(u32, 512), std.mem.readInt(u32, out[20..24], .little));
    try testing.expectEqual(@as(usize, 24), out.len);
}

test "a read-only volume says so in its attributes" {
    var buf: [128]u8 = undefined;
    var w = wire.Writer.init(&buf);
    try writeFsInfo(&w, .attribute, .{ .total_bytes = 0, .free_bytes = 0, .read_only = true });
    const attributes = std.mem.readInt(u32, w.written()[0..4], .little);
    try testing.expect(attributes & 0x0008_0000 != 0);
}

test "the security descriptor is self-relative and internally consistent" {
    var buf: [128]u8 = undefined;
    var w = wire.Writer.init(&buf);
    try writeSecurityDescriptor(&w, 0x7, full_access); // owner | group | dacl
    const out = w.written();

    try testing.expectEqual(@as(u8, 1), out[0]);
    const control = std.mem.readInt(u16, out[2..4], .little);
    try testing.expect(control & 0x8000 != 0); // self-relative
    try testing.expect(control & 0x0004 != 0); // DACL present

    const owner_at = std.mem.readInt(u32, out[4..8], .little);
    const dacl_at = std.mem.readInt(u32, out[16..20], .little);
    try testing.expectEqual(@as(u32, 20), owner_at);
    try testing.expect(dacl_at + 8 <= out.len);

    const acl_size = std.mem.readInt(u16, out[dacl_at + 2 ..][0..2], .little);
    try testing.expectEqual(dacl_at + acl_size, out.len); // the ACL ends the descriptor
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, out[dacl_at + 4 ..][0..2], .little));
}

test "asking for only the owner leaves the DACL out entirely" {
    var buf: [128]u8 = undefined;
    var w = wire.Writer.init(&buf);
    try writeSecurityDescriptor(&w, 0x1, full_access);
    const out = w.written();
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, out[16..20], .little));
    try testing.expect(std.mem.readInt(u16, out[2..4], .little) & 0x0004 == 0);
    try testing.expectEqual(@as(usize, 36), out.len); // header + one SID
}

test "set-info parsers read what clients send" {
    const rename_buf = [_]u8{1} ++ [_]u8{0} ** 7 ++ [_]u8{0} ** 8 ++
        [_]u8{ 4, 0, 0, 0 } ++ [_]u8{ 'a', 0, 'b', 0 };
    const rename = try parseRename(&rename_buf);
    try testing.expect(rename.replace);
    try testing.expectEqualSlices(u8, &.{ 'a', 0, 'b', 0 }, rename.name_utf16);

    try testing.expect(try parseDisposition(&.{1}));
    try testing.expect(!try parseDisposition(&.{0}));
    try testing.expectEqual(@as(u64, 0x1000), try parseEndOfFile(&.{ 0, 0x10, 0, 0, 0, 0, 0, 0 }));
}

test "a zero or frozen timestamp in SET_INFO means leave it alone" {
    var buf: [40]u8 = @splat(0);
    std.mem.writeInt(u64, buf[8..16], std.math.maxInt(u64), .little); // accessed: frozen
    std.mem.writeInt(u64, buf[16..24], 12345, .little); // modified: set it
    std.mem.writeInt(u32, buf[32..36], 0x20, .little); // attributes: archive
    const changes = try parseBasic(&buf);
    try testing.expectEqual(@as(?u64, null), changes.created);
    try testing.expectEqual(@as(?u64, null), changes.accessed);
    try testing.expectEqual(@as(?u64, 12345), changes.modified);
    try testing.expect(changes.attributes.?.archive);
}
