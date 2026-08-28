const std = @import("std");

/// Overwrites engine-owned secret bytes through volatile stores so the wipe
/// cannot be removed as a dead store.
pub fn bytes(buf: []u8) void {
    const volatile_buf: []volatile u8 = @volatileCast(buf);
    @memset(volatile_buf, 0);
}

/// Securely wipes the object referenced by `value`.
pub fn value(value_ptr: anytype) void {
    bytes(std.mem.asBytes(value_ptr));
}

test "secure wipe clears bytes and values" {
    var buf = [_]u8{0xa5} ** 32;
    bytes(&buf);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &buf);

    var secret: u64 = std.math.maxInt(u64);
    value(&secret);
    try std.testing.expectEqual(@as(u64, 0), secret);
}
