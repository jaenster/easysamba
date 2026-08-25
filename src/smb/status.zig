//! NTSTATUS values, and the mapping from the VFS adapter's error set onto them.
//! Only the codes an SMB2 file server actually returns are listed; a client
//! reacts to these very differently, so picking the right one is behaviour, not
//! cosmetics.

const std = @import("std");

pub const Status = u32;

pub const SUCCESS: Status = 0x0000_0000;
pub const PENDING: Status = 0x0000_0103;
pub const NOTIFY_ENUM_DIR: Status = 0x0000_010C;
pub const BUFFER_OVERFLOW: Status = 0x8000_0005;
pub const NO_MORE_FILES: Status = 0x8000_0006;

pub const UNSUCCESSFUL: Status = 0xC000_0001;
pub const NOT_IMPLEMENTED: Status = 0xC000_0002;
pub const INVALID_INFO_CLASS: Status = 0xC000_0003;
pub const INFO_LENGTH_MISMATCH: Status = 0xC000_0004;
pub const ACCESS_VIOLATION: Status = 0xC000_0005;
pub const INVALID_HANDLE: Status = 0xC000_0008;
pub const INVALID_PARAMETER: Status = 0xC000_000D;
pub const NO_SUCH_DEVICE: Status = 0xC000_000E;
pub const NO_SUCH_FILE: Status = 0xC000_000F;
pub const INVALID_DEVICE_REQUEST: Status = 0xC000_0010;
pub const END_OF_FILE: Status = 0xC000_0011;
pub const MORE_PROCESSING_REQUIRED: Status = 0xC000_0016;
pub const ACCESS_DENIED: Status = 0xC000_0022;
pub const BUFFER_TOO_SMALL: Status = 0xC000_0023;
pub const OBJECT_NAME_INVALID: Status = 0xC000_0033;
pub const OBJECT_NAME_NOT_FOUND: Status = 0xC000_0034;
pub const OBJECT_NAME_COLLISION: Status = 0xC000_0035;
pub const OBJECT_PATH_NOT_FOUND: Status = 0xC000_003A;
pub const OBJECT_PATH_SYNTAX_BAD: Status = 0xC000_003B;
pub const SHARING_VIOLATION: Status = 0xC000_0043;
pub const FILE_LOCK_CONFLICT: Status = 0xC000_0054;
pub const LOCK_NOT_GRANTED: Status = 0xC000_0055;
pub const DELETE_PENDING: Status = 0xC000_0056;
pub const LOGON_FAILURE: Status = 0xC000_006D;
pub const ACCOUNT_RESTRICTION: Status = 0xC000_006E;
pub const RANGE_NOT_LOCKED: Status = 0xC000_007E;
pub const DISK_FULL: Status = 0xC000_007F;
pub const NO_MEMORY: Status = 0xC000_009A;
pub const FILE_IS_A_DIRECTORY: Status = 0xC000_00BA;
pub const NOT_SUPPORTED: Status = 0xC000_00BB;
pub const BAD_NETWORK_NAME: Status = 0xC000_00CC;
pub const NOT_A_DIRECTORY: Status = 0xC000_0103;
pub const CANCELLED: Status = 0xC000_0120;
pub const DIRECTORY_NOT_EMPTY: Status = 0xC000_0101;
pub const FILE_CLOSED: Status = 0xC000_0128;
pub const USER_SESSION_DELETED: Status = 0xC000_00D5;
pub const NETWORK_SESSION_EXPIRED: Status = 0xC000_035C;
pub const TOO_MANY_OPENED_FILES: Status = 0xC000_011F;
pub const INSUFF_SERVER_RESOURCES: Status = 0xC000_0205;
pub const NOT_SAME_DEVICE: Status = 0xC000_00D4;
pub const REQUEST_NOT_ACCEPTED: Status = 0xC000_00D0;
pub const INVALID_SMB: Status = 0x0001_0002;
pub const SMB_BAD_TID: Status = 0x0005_0002;
pub const SMB_BAD_UID: Status = 0x005B_0002;

pub fn isError(s: Status) bool {
    return s & 0xC000_0000 == 0xC000_0000;
}

/// Best-effort name for logging. Unlisted codes print as hex at the call site.
pub fn name(s: Status) ?[]const u8 {
    return switch (s) {
        SUCCESS => "SUCCESS",
        MORE_PROCESSING_REQUIRED => "MORE_PROCESSING_REQUIRED",
        NO_MORE_FILES => "NO_MORE_FILES",
        ACCESS_DENIED => "ACCESS_DENIED",
        LOGON_FAILURE => "LOGON_FAILURE",
        OBJECT_NAME_NOT_FOUND => "OBJECT_NAME_NOT_FOUND",
        OBJECT_PATH_NOT_FOUND => "OBJECT_PATH_NOT_FOUND",
        OBJECT_NAME_COLLISION => "OBJECT_NAME_COLLISION",
        NOT_SUPPORTED => "NOT_SUPPORTED",
        INVALID_PARAMETER => "INVALID_PARAMETER",
        BAD_NETWORK_NAME => "BAD_NETWORK_NAME",
        FILE_IS_A_DIRECTORY => "FILE_IS_A_DIRECTORY",
        NOT_A_DIRECTORY => "NOT_A_DIRECTORY",
        DIRECTORY_NOT_EMPTY => "DIRECTORY_NOT_EMPTY",
        INVALID_HANDLE => "INVALID_HANDLE",
        DISK_FULL => "DISK_FULL",
        FILE_LOCK_CONFLICT => "FILE_LOCK_CONFLICT",
        LOCK_NOT_GRANTED => "LOCK_NOT_GRANTED",
        RANGE_NOT_LOCKED => "RANGE_NOT_LOCKED",
        END_OF_FILE => "END_OF_FILE",
        else => null,
    };
}

test "isError separates failures from informational codes" {
    try std.testing.expect(isError(ACCESS_DENIED));
    try std.testing.expect(!isError(SUCCESS));
    try std.testing.expect(!isError(NO_MORE_FILES)); // 0x8... is a warning, not an error
}
