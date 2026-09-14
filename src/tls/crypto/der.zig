//! Bounded DER framing for primitive key/algorithm encodings. This is not an
//! X.509 parser or certificate path validator.
const std = @import("std");
const Der = std.crypto.Certificate.der;
pub const Error = error{InvalidEncoding};

pub const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn take(self: *Reader, expected_tag: u8) Error![]const u8 {
        if (self.offset > self.bytes.len) return error.InvalidEncoding;
        const rest = self.bytes[self.offset..];
        if (rest.len < 2 or rest[0] != expected_tag) return error.InvalidEncoding;
        var header_len: usize = 2;
        var length: usize = rest[1];
        if (rest[1] & 0x80 != 0) {
            const length_bytes = rest[1] & 0x7f;
            if (length_bytes == 0 or length_bytes > 4 or rest.len < 2 + @as(usize, length_bytes))
                return error.InvalidEncoding;
            if (rest[2] == 0) return error.InvalidEncoding;
            length = 0;
            for (rest[2..][0..length_bytes]) |byte| {
                length = std.math.mul(usize, length, 256) catch return error.InvalidEncoding;
                length = std.math.add(usize, length, byte) catch return error.InvalidEncoding;
            }
            if (length < 128) return error.InvalidEncoding;
            header_len += length_bytes;
        }
        if (length > rest.len - header_len or length > std.math.maxInt(u32) - header_len)
            return error.InvalidEncoding;
        // std's DER element primitive assumes valid index/length bounds.
        // Only call it after proving those bounds and canonical framing.
        const parsed = Der.Element.parse(rest, 0) catch return error.InvalidEncoding;
        self.offset += parsed.slice.end;
        return rest[parsed.slice.start..parsed.slice.end];
    }

    pub const Element = struct { tag: u8, encoded: []const u8, content: []const u8 };

    pub fn element(self: *Reader) Error!Element {
        if (self.offset >= self.bytes.len) return error.InvalidEncoding;
        const start = self.offset;
        const tag = self.bytes[start];
        if (tag & 0x1f == 0x1f) return error.InvalidEncoding;
        const content = try self.take(tag);
        return .{ .tag = tag, .encoded = self.bytes[start..self.offset], .content = content };
    }

    pub fn finish(self: Reader) Error!void {
        if (self.offset != self.bytes.len) return error.InvalidEncoding;
    }
};

pub fn sequence(bytes: []const u8) Error!Reader {
    var outer: Reader = .{ .bytes = bytes };
    const inner = try outer.take(0x30);
    try outer.finish();
    return .{ .bytes = inner };
}

pub fn positiveInteger(reader: *Reader) Error![]const u8 {
    const bytes = try reader.take(0x02);
    if (bytes.len == 0 or bytes[0] & 0x80 != 0) return error.InvalidEncoding;
    if (bytes[0] == 0) {
        if (bytes.len == 1 or bytes[1] & 0x80 == 0) return error.InvalidEncoding;
        return bytes[1..];
    }
    return bytes;
}

pub fn validateRsaPublicKey(bytes: []const u8) Error!void {
    var reader = try sequence(bytes);
    _ = try positiveInteger(&reader);
    _ = try positiveInteger(&reader);
    try reader.finish();
}

test "bounded DER rejects truncated noncanonical and trailing fields" {
    const testing = std.testing;
    for ([_][]const u8{ "", "\x30", "\x30\x80", "\x30\x81\x00", "\x30\x82\x00\x80", "\x30\x02\x00", "\x30\x00\x00", "\x30\xff" }) |input| {
        try testing.expectError(error.InvalidEncoding, sequence(input));
    }
    var reader = try sequence("\x30\x00");
    try testing.expectError(error.InvalidEncoding, reader.take(2));
    for ([_][]const u8{ "\x30\x06\x02\x01\x80\x02\x01\x03", "\x30\x07\x02\x02\x00\x01\x02\x01\x03", "\x30\x05\x02\x00\x02\x01\x03" }) |input| {
        try testing.expectError(error.InvalidEncoding, validateRsaPublicKey(input));
    }
}
