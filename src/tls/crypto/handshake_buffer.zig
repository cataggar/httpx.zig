const std = @import("std");
const wipe = @import("secure_wipe.zig");

pub const Buffer = struct {
    allocator: std.mem.Allocator,
    maximum_message: usize,
    bytes: []u8 = &.{},
    start: usize = 0,
    end: usize = 0,

    pub fn init(allocator: std.mem.Allocator, maximum: usize) Buffer {
        return .{ .allocator = allocator, .maximum_message = maximum };
    }

    pub fn deinit(self: *Buffer) void {
        wipe.bytes(self.bytes);
        self.allocator.free(self.bytes);
        self.bytes = &.{};
        self.start = 0;
        self.end = 0;
    }

    pub fn pendingLength(self: *const Buffer) usize {
        return self.end - self.start;
    }

    pub fn append(self: *Buffer, fragment: []const u8) !void {
        const pending = self.pendingLength();
        const maximum_buffer = std.math.add(usize, self.maximum_message, 16384) catch return error.TlsRecordOverflow;
        if (fragment.len > maximum_buffer - pending) return error.TlsRecordOverflow;
        if (self.start != 0) {
            std.mem.copyForwards(u8, self.bytes[0..pending], self.bytes[self.start..self.end]);
            wipe.bytes(self.bytes[pending..self.end]);
            self.start = 0;
            self.end = pending;
        }
        const required = pending + fragment.len;
        if (required > self.bytes.len) {
            var capacity: usize = @max(512, self.bytes.len);
            while (capacity < required) capacity = @min(maximum_buffer, capacity * 2);
            const replacement = try self.allocator.alloc(u8, capacity);
            @memcpy(replacement[0..pending], self.bytes[0..pending]);
            wipe.bytes(self.bytes);
            self.allocator.free(self.bytes);
            self.bytes = replacement;
        }
        @memcpy(self.bytes[self.end..][0..fragment.len], fragment);
        self.end += fragment.len;
    }

    pub fn peek(self: *Buffer) !?[]u8 {
        const pending = self.pendingLength();
        if (pending < 4) return null;
        const length = 4 + @as(usize, std.mem.readInt(u24, self.bytes[self.start + 1 ..][0..3], .big));
        if (length > self.maximum_message) return error.TlsRecordOverflow;
        if (length > pending) return null;
        return self.bytes[self.start..][0..length];
    }

    pub fn consume(self: *Buffer, length: usize) void {
        std.debug.assert(length <= self.pendingLength());
        self.start += length;
    }
};

test "handshake buffer retains partial headers large messages and coalesced successors" {
    var buffer = Buffer.init(std.testing.allocator, 65536);
    defer buffer.deinit();
    var message: [25004]u8 = @splat(0x42);
    message[0] = 11;
    std.mem.writeInt(u24, message[1..4], message.len - 4, .big);
    try buffer.append(message[0..2]);
    try std.testing.expect(try buffer.peek() == null);
    try buffer.append(message[2..16000]);
    try std.testing.expect(try buffer.peek() == null);
    try buffer.append(message[16000..]);
    try buffer.append("\x0e\x00\x00\x00");
    try std.testing.expectEqualSlices(u8, &message, (try buffer.peek()).?);
    buffer.consume(message.len);
    try std.testing.expectEqualStrings("\x0e\x00\x00\x00", (try buffer.peek()).?);
    buffer.consume(4);
    try buffer.append("\x0e\x00\x00\x00");
    try std.testing.expectEqualStrings("\x0e\x00\x00\x00", (try buffer.peek()).?);
}

test "handshake buffer rejects declared limits and preserves allocation failures" {
    var buffer = Buffer.init(std.testing.allocator, 64);
    defer buffer.deinit();
    try buffer.append("\x0b\x00\x01\x00");
    try std.testing.expectError(error.TlsRecordOverflow, buffer.peek());
    var failing = Buffer.init(std.testing.failing_allocator, 64);
    defer failing.deinit();
    try std.testing.expectError(error.OutOfMemory, failing.append("\x0e\x00\x00\x00"));
    try std.testing.expectEqual(0, failing.pendingLength());
}
