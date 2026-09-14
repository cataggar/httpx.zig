//! Deterministic CTL metadata fixtures; no root store writes or signing keys.
const std = @import("std");
const ctl = @import("windows_ctl.zig");
const Allocator = std.mem.Allocator;

pub const Attribute = struct { id: u32, value: []const u8 };
pub const Entry = struct { identifier: []const u8, attributes: []const Attribute = &.{} };
pub const Options = struct {
    usage_oid: []const u8 = ctl.authroot_usage,
    algorithm_oid: []const u8 = "\x2b\x0e\x03\x02\x1a",
    algorithm_parameters: []const u8 = "",
    this_update: []const u8 = "250101000000Z",
    next_update: ?[]const u8 = "350101000000Z",
    entries: []const Entry = &.{},
    extra_tail: []const u8 = &.{},
};

pub fn content(allocator: Allocator, options: Options) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    var entries: std.ArrayList([]const u8) = .empty;
    for (options.entries) |entry| {
        var attributes: std.ArrayList([]const u8) = .empty;
        for (entry.attributes) |attribute| {
            var encoded_id: [5]u8 = undefined;
            var length: usize = 1;
            var number = attribute.id;
            encoded_id[4] = @intCast(number & 0x7f);
            while (number > 127) {
                number >>= 7;
                encoded_id[4 - length] = @as(u8, @intCast(number & 0x7f)) | 0x80;
                length += 1;
            }
            const oid = try join(scratch, &.{ "\x2b\x06\x01\x04\x01\x82\x37\x0a\x0b", encoded_id[5 - length ..] });
            try attributes.append(scratch, try element(scratch, 0x30, try join(scratch, &.{
                try element(scratch, 0x06, oid),
                try element(scratch, 0x31, try element(scratch, 0x04, attribute.value)),
            })));
        }
        try entries.append(scratch, try element(scratch, 0x30, try join(scratch, &.{
            try element(scratch, 0x04, entry.identifier),
            try element(scratch, 0x31, try join(scratch, attributes.items)),
        })));
    }
    const encoded = try element(scratch, 0x30, try join(scratch, &.{
        try element(scratch, 0x30, try element(scratch, 0x06, options.usage_oid)),
        "\x04\x07fixture",
        "\x02\x01\x01",
        try element(scratch, 0x17, options.this_update),
        if (options.next_update) |time| try element(scratch, 0x17, time) else "",
        try element(scratch, 0x30, try join(scratch, &.{
            try element(scratch, 0x06, options.algorithm_oid),
            options.algorithm_parameters,
        })),
        try element(scratch, 0x30, try join(scratch, entries.items)),
        options.extra_tail,
    }));
    return allocator.dupe(u8, encoded);
}

/// A process-local, unsigned PKCS#7 SignedData envelope for decoder testing.
/// It is not an authenticated source and must never be imported as root trust.
pub fn envelope(allocator: Allocator, ctl_content: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    const signed = try element(scratch, 0x30, try join(scratch, &.{
        "\x02\x01\x01\x31\x00",
        try element(scratch, 0x30, try join(scratch, &.{
            "\x06\x09\x2b\x06\x01\x04\x01\x82\x37\x0a\x01",
            try element(scratch, 0xa0, ctl_content),
        })),
        "\x31\x00",
    }));
    const encoded = try element(scratch, 0x30, try join(scratch, &.{
        "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02",
        try element(scratch, 0xa0, signed),
    }));
    return allocator.dupe(u8, encoded);
}

pub fn element(allocator: Allocator, tag: u8, bytes: []const u8) ![]const u8 {
    var header: [10]u8 = undefined;
    header[0] = tag;
    var length: usize = 2;
    if (bytes.len < 128) {
        header[1] = @intCast(bytes.len);
    } else {
        var encoded: [8]u8 = undefined;
        std.mem.writeInt(u64, &encoded, bytes.len, .big);
        var start: usize = 0;
        while (encoded[start] == 0) start += 1;
        header[1] = 0x80 | @as(u8, @intCast(8 - start));
        @memcpy(header[2..][0 .. 8 - start], encoded[start..]);
        length += 8 - start;
    }
    return join(allocator, &.{ header[0..length], bytes });
}

pub fn join(allocator: Allocator, parts: []const []const u8) ![]const u8 {
    var output: std.ArrayList(u8) = .empty;
    for (parts) |part| try output.appendSlice(allocator, part);
    return output.toOwnedSlice(allocator);
}
