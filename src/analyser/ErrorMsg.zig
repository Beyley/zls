const std = @import("std");
const types = @import("../lsp.zig");
const offsets = @import("../offsets.zig");

const InternPool = @import("InternPool.zig");
const Index = InternPool.Index;
const Key = InternPool.Key;

const ErrorMsg = @This();

pub const Data = union(enum) {
    /// zig: expected type 'type', found '{}'
    expected_type_type: struct {
        actual: Index,
    },
    /// zig: expected type '{}', found '{}'
    expected_type: struct {
        expected_type: Index,
        actual: Index,
    },
    /// zig: comparison of '{}' with null
    compare_eq_with_null: struct {
        non_null_type: Index,
    },
};

loc: offsets.Loc,
data: Data,

pub fn message(
    self: ErrorMsg,
    allocator: std.mem.Allocator,
    ip: InternPool,
) error{OutOfMemory}![]u8 {
    return switch (self.data) {
        .expected_type_type => |info| std.fmt.allocPrint(
            allocator,
            "expected type 'type', found '{}'",
            .{ip.indexToKey(info.actual).typeOf().fmt(ip)},
        ),
        .expected_type => |info| std.fmt.allocPrint(
            allocator,
            "expected type '{}', found '{}'",
            .{ info.expected_type.fmt(ip), ip.indexToKey(info.actual).typeOf().fmt(ip) },
        ),
        .compare_eq_with_null => |info| std.fmt.allocPrint(
            allocator,
            "comparison of '{}' with null",
            .{info.non_null_type.fmt(ip)},
        ),
    };
}
