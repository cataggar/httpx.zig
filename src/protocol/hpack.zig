//! HPACK Header Compression for HTTP/2
//!
//! Implements RFC 7541 - HPACK: Header Compression for HTTP/2
//!
//! Features:
//! - Static table with 61 pre-defined headers
//! - Dynamic table with configurable size
//! - Huffman encoding/decoding
//! - Integer encoding with prefix bits
//! - Indexed header field representation
//! - Literal header field representations

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// HPACK static table entries (RFC 7541 Appendix A)
/// Index 1-61 are pre-defined header name/value pairs
pub const StaticTable = struct {
    pub const Entry = struct { name: []const u8, value: []const u8 };

    pub const entries = [_]Entry{
        .{ .name = ":authority", .value = "" }, // 1
        .{ .name = ":method", .value = "GET" }, // 2
        .{ .name = ":method", .value = "POST" }, // 3
        .{ .name = ":path", .value = "/" }, // 4
        .{ .name = ":path", .value = "/index.html" }, // 5
        .{ .name = ":scheme", .value = "http" }, // 6
        .{ .name = ":scheme", .value = "https" }, // 7
        .{ .name = ":status", .value = "200" }, // 8
        .{ .name = ":status", .value = "204" }, // 9
        .{ .name = ":status", .value = "206" }, // 10
        .{ .name = ":status", .value = "304" }, // 11
        .{ .name = ":status", .value = "400" }, // 12
        .{ .name = ":status", .value = "404" }, // 13
        .{ .name = ":status", .value = "500" }, // 14
        .{ .name = "accept-charset", .value = "" }, // 15
        .{ .name = "accept-encoding", .value = "gzip, deflate" }, // 16
        .{ .name = "accept-language", .value = "" }, // 17
        .{ .name = "accept-ranges", .value = "" }, // 18
        .{ .name = "accept", .value = "" }, // 19
        .{ .name = "access-control-allow-origin", .value = "" }, // 20
        .{ .name = "age", .value = "" }, // 21
        .{ .name = "allow", .value = "" }, // 22
        .{ .name = "authorization", .value = "" }, // 23
        .{ .name = "cache-control", .value = "" }, // 24
        .{ .name = "content-disposition", .value = "" }, // 25
        .{ .name = "content-encoding", .value = "" }, // 26
        .{ .name = "content-language", .value = "" }, // 27
        .{ .name = "content-length", .value = "" }, // 28
        .{ .name = "content-location", .value = "" }, // 29
        .{ .name = "content-range", .value = "" }, // 30
        .{ .name = "content-type", .value = "" }, // 31
        .{ .name = "cookie", .value = "" }, // 32
        .{ .name = "date", .value = "" }, // 33
        .{ .name = "etag", .value = "" }, // 34
        .{ .name = "expect", .value = "" }, // 35
        .{ .name = "expires", .value = "" }, // 36
        .{ .name = "from", .value = "" }, // 37
        .{ .name = "host", .value = "" }, // 38
        .{ .name = "if-match", .value = "" }, // 39
        .{ .name = "if-modified-since", .value = "" }, // 40
        .{ .name = "if-none-match", .value = "" }, // 41
        .{ .name = "if-range", .value = "" }, // 42
        .{ .name = "if-unmodified-since", .value = "" }, // 43
        .{ .name = "last-modified", .value = "" }, // 44
        .{ .name = "link", .value = "" }, // 45
        .{ .name = "location", .value = "" }, // 46
        .{ .name = "max-forwards", .value = "" }, // 47
        .{ .name = "proxy-authenticate", .value = "" }, // 48
        .{ .name = "proxy-authorization", .value = "" }, // 49
        .{ .name = "range", .value = "" }, // 50
        .{ .name = "referer", .value = "" }, // 51
        .{ .name = "refresh", .value = "" }, // 52
        .{ .name = "retry-after", .value = "" }, // 53
        .{ .name = "server", .value = "" }, // 54
        .{ .name = "set-cookie", .value = "" }, // 55
        .{ .name = "strict-transport-security", .value = "" }, // 56
        .{ .name = "transfer-encoding", .value = "" }, // 57
        .{ .name = "user-agent", .value = "" }, // 58
        .{ .name = "vary", .value = "" }, // 59
        .{ .name = "via", .value = "" }, // 60
        .{ .name = "www-authenticate", .value = "" }, // 61
    };

    /// Looks up a header by index (1-based).
    pub fn get(index: usize) ?Entry {
        if (index == 0 or index > entries.len) return null;
        return entries[index - 1];
    }

    /// Finds the index of a header name (returns first match).
    pub fn findName(name: []const u8) ?usize {
        for (entries, 0..) |entry, i| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) {
                return i + 1;
            }
        }
        return null;
    }

    /// Finds the index of a header name+value pair.
    pub fn findNameValue(name: []const u8, value: []const u8) ?usize {
        for (entries, 0..) |entry, i| {
            if (std.ascii.eqlIgnoreCase(entry.name, name) and mem.eql(u8, entry.value, value)) {
                return i + 1;
            }
        }
        return null;
    }
};

/// Dynamic table entry
pub const DynamicEntry = struct {
    name: []u8,
    value: []u8,

    pub fn size(self: DynamicEntry) usize {
        // RFC 7541: size = len(name) + len(value) + 32
        return self.name.len + self.value.len + 32;
    }
};

/// HPACK dynamic table with FIFO eviction
pub const DynamicTable = struct {
    allocator: Allocator,
    entries: std.ArrayList(DynamicEntry) = .empty,
    current_size: usize = 0,
    max_size: usize = 4096, // Default per RFC 7541

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn initWithSize(allocator: Allocator, max_size: usize) Self {
        return .{ .allocator = allocator, .max_size = max_size };
    }

    pub fn deinit(self: *Self) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
        self.entries.deinit(self.allocator);
    }

    /// Adds a new entry to the beginning of the dynamic table.
    /// Evicts old entries if necessary to fit within max_size.
    pub fn add(self: *Self, name: []const u8, value: []const u8) !void {
        const name_value_size = std.math.add(usize, name.len, value.len) catch
            return error.HeaderSizeOverflow;
        const entry_size = std.math.add(usize, name_value_size, 32) catch
            return error.HeaderSizeOverflow;

        if (entry_size > self.max_size) {
            while (self.entries.items.len > 0) self.evictOne();
            return;
        }

        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        // Mutate only after every fallible allocation succeeds.
        while (entry_size > self.max_size - self.current_size and self.entries.items.len > 0) {
            self.evictOne();
        }
        self.entries.insertAssumeCapacity(0, .{
            .name = name_copy,
            .value = value_copy,
        });
        self.current_size += entry_size;
    }

    /// Evicts the oldest entry (last in list).
    fn evictOne(self: *Self) void {
        if (self.entries.items.len == 0) return;
        const entry = self.entries.pop().?;
        self.current_size -= entry.name.len + entry.value.len + 32;
        self.allocator.free(entry.name);
        self.allocator.free(entry.value);
    }

    /// Gets an entry by index (0-based within dynamic table).
    pub fn get(self: *const Self, index: usize) ?StaticTable.Entry {
        if (index >= self.entries.items.len) return null;
        const entry = self.entries.items[index];
        return .{ .name = entry.name, .value = entry.value };
    }

    /// Updates the maximum size and evicts entries if needed.
    pub fn setMaxSize(self: *Self, new_max: usize) void {
        self.max_size = new_max;
        while (self.current_size > self.max_size and self.entries.items.len > 0) {
            self.evictOne();
        }
    }

    pub fn len(self: *const Self) usize {
        return self.entries.items.len;
    }
};

/// HPACK encoder/decoder context
pub const HPACKContext = struct {
    allocator: Allocator,
    dynamic_table: DynamicTable,
    max_allowed_table_size: usize = 4096,
    pending_encoder_table_size: ?usize = null,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .dynamic_table = DynamicTable.init(allocator),
            .max_allowed_table_size = 4096,
        };
    }

    pub fn initWithTableSize(allocator: Allocator, max_table_size: usize) Self {
        return .{
            .allocator = allocator,
            .dynamic_table = DynamicTable.initWithSize(allocator, max_table_size),
            .max_allowed_table_size = max_table_size,
        };
    }

    pub fn deinit(self: *Self) void {
        self.dynamic_table.deinit();
    }

    pub fn setMaxAllowedTableSize(self: *Self, max_table_size: usize) void {
        self.max_allowed_table_size = max_table_size;
        if (self.dynamic_table.max_size > max_table_size) {
            self.dynamic_table.setMaxSize(max_table_size);
        }
    }

    /// Applies the peer's encoder limit immediately and queues the required
    /// HPACK table-size update for the start of the next encoded block.
    pub fn setEncoderTableSize(self: *Self, max_table_size: usize) void {
        self.dynamic_table.setMaxSize(max_table_size);
        self.pending_encoder_table_size = max_table_size;
    }

    /// Looks up a header by combined index (static + dynamic).
    /// Index 1-61 = static table, 62+ = dynamic table
    pub fn getByIndex(self: *const Self, index: usize) ?StaticTable.Entry {
        if (index <= StaticTable.entries.len) {
            return StaticTable.get(index);
        }
        const dynamic_index = index - StaticTable.entries.len - 1;
        return self.dynamic_table.get(dynamic_index);
    }
};

/// Encodes an integer with the given prefix bits.
/// prefix_bits: number of bits available in the first byte (1-8)
pub fn encodeInteger(value: u64, prefix_bits: u4, out: []u8) !usize {
    if (prefix_bits == 0 or prefix_bits > 8) return error.InvalidPrefixBits;
    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;

    if (value < max_prefix) {
        if (out.len < 1) return error.BufferTooSmall;
        out[0] = @intCast(value);
        return 1;
    }

    if (out.len < 1) return error.BufferTooSmall;
    out[0] = @intCast(max_prefix);

    var remaining = value - max_prefix;
    var i: usize = 1;

    while (remaining >= 128) {
        if (i >= out.len) return error.BufferTooSmall;
        out[i] = @intCast((remaining & 0x7F) | 0x80);
        remaining >>= 7;
        i += 1;
    }

    if (i >= out.len) return error.BufferTooSmall;
    out[i] = @intCast(remaining);
    return i + 1;
}

/// Decodes an integer with the given prefix bits.
/// Returns the value and number of bytes consumed.
pub fn decodeInteger(data: []const u8, prefix_bits: u4) !struct { value: u64, len: usize } {
    if (data.len == 0) return error.UnexpectedEof;
    if (prefix_bits == 0 or prefix_bits > 8) return error.InvalidPrefixBits;

    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;
    const first_byte_mask: u8 = @intCast(max_prefix);

    var value: u64 = data[0] & first_byte_mask;

    if (value < max_prefix) {
        return .{ .value = value, .len = 1 };
    }

    var i: usize = 1;
    var shift: u8 = 0;

    while (i < data.len) {
        const b = data[i];
        const payload = @as(u64, b & 0x7F);
        if (shift >= 64) return error.IntegerOverflow;
        const shift_amount: std.math.Log2Int(u64) = @intCast(shift);
        if (payload > (@as(u64, std.math.maxInt(u64)) >> shift_amount)) {
            return error.IntegerOverflow;
        }
        value = std.math.add(
            u64,
            value,
            payload << shift_amount,
        ) catch return error.IntegerOverflow;
        i += 1;

        if (b & 0x80 == 0) {
            return .{ .value = value, .len = i };
        }

        if (shift > 56) return error.IntegerOverflow;
        shift += 7;
        if (i > 11) return error.IntegerOverflow;
    }

    return error.UnexpectedEof;
}

/// Encodes a string (with optional Huffman encoding).
pub fn encodeString(str: []const u8, use_huffman: bool, allocator: Allocator, out: *std.ArrayList(u8)) !void {
    if (use_huffman) {
        const encoded = try HuffmanCodec.encode(str, allocator);
        defer allocator.free(encoded);

        // Length with H bit set
        var len_buf: [10]u8 = undefined;
        const len_bytes = try encodeInteger(encoded.len, 7, &len_buf);
        len_buf[0] |= 0x80; // Set Huffman flag
        try out.appendSlice(allocator, len_buf[0..len_bytes]);
        try out.appendSlice(allocator, encoded);
    } else {
        // Length without H bit
        var len_buf: [10]u8 = undefined;
        const len_bytes = try encodeInteger(str.len, 7, &len_buf);
        try out.appendSlice(allocator, len_buf[0..len_bytes]);
        try out.appendSlice(allocator, str);
    }
}

/// Decodes a string (handles Huffman encoding automatically).
pub fn decodeString(data: []const u8, allocator: Allocator) !struct { value: []u8, len: usize } {
    if (data.len == 0) return error.UnexpectedEof;

    const huffman = (data[0] & 0x80) != 0;
    const len_result = try decodeInteger(data, 7);
    const str_len = std.math.cast(usize, len_result.value) orelse
        return error.StringLengthOverflow;
    const total_len = std.math.add(usize, len_result.len, str_len) catch
        return error.StringLengthOverflow;

    if (data.len < total_len) return error.UnexpectedEof;

    const str_data = data[len_result.len..total_len];

    if (huffman) {
        const decoded = try HuffmanCodec.decode(str_data, allocator);
        return .{ .value = decoded, .len = total_len };
    } else {
        const copy = try allocator.dupe(u8, str_data);
        return .{ .value = copy, .len = total_len };
    }
}

/// Huffman codec for HPACK encoding/decoding.
pub const HuffmanCodec = struct {
    // Huffman codes and lengths for each byte value (0-255) plus EOS
    // These are from RFC 7541 Appendix B
    const codes = [256]u32{
        0x1ff8,    0x7fffd8,  0xfffffe2,  0xfffffe3, 0xfffffe4, 0xfffffe5,  0xfffffe6,  0xfffffe7,
        0xfffffe8, 0xffffea,  0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb,  0xfffffec,
        0xfffffed, 0xfffffee, 0xfffffef,  0xffffff0, 0xffffff1, 0xffffff2,  0x3ffffffe, 0xffffff3,
        0xffffff4, 0xffffff5, 0xffffff6,  0xffffff7, 0xffffff8, 0xffffff9,  0xffffffa,  0xffffffb,
        0x14,      0x3f8,     0x3f9,      0xffa,     0x1ff9,    0x15,       0xf8,       0x7fa,
        0x3fa,     0x3fb,     0xf9,       0x7fb,     0xfa,      0x16,       0x17,       0x18,
        0x0,       0x1,       0x2,        0x19,      0x1a,      0x1b,       0x1c,       0x1d,
        0x1e,      0x1f,      0x5c,       0xfb,      0x7ffc,    0x20,       0xffb,      0x3fc,
        0x1ffa,    0x21,      0x5d,       0x5e,      0x5f,      0x60,       0x61,       0x62,
        0x63,      0x64,      0x65,       0x66,      0x67,      0x68,       0x69,       0x6a,
        0x6b,      0x6c,      0x6d,       0x6e,      0x6f,      0x70,       0x71,       0x72,
        0xfc,      0x73,      0xfd,       0x1ffb,    0x7fff0,   0x1ffc,     0x3ffc,     0x22,
        0x7ffd,    0x3,       0x23,       0x4,       0x24,      0x5,        0x25,       0x26,
        0x27,      0x6,       0x74,       0x75,      0x28,      0x29,       0x2a,       0x7,
        0x2b,      0x76,      0x2c,       0x8,       0x9,       0x2d,       0x77,       0x78,
        0x79,      0x7a,      0x7b,       0x7ffe,    0x7fc,     0x3ffd,     0x1ffd,     0xffffffc,
        0xfffe6,   0x3fffd2,  0xfffe7,    0xfffe8,   0x3fffd3,  0x3fffd4,   0x3fffd5,   0x7fffd9,
        0x3fffd6,  0x7fffda,  0x7fffdb,   0x7fffdc,  0x7fffdd,  0x7fffde,   0xffffeb,   0x7fffdf,
        0xffffec,  0xffffed,  0x3fffd7,   0x7fffe0,  0xffffee,  0x7fffe1,   0x7fffe2,   0x7fffe3,
        0x7fffe4,  0x1fffdc,  0x3fffd8,   0x7fffe5,  0x3fffd9,  0x7fffe6,   0x7fffe7,   0xffffef,
        0x3fffda,  0x1fffdd,  0xfffe9,    0x3fffdb,  0x3fffdc,  0x7fffe8,   0x7fffe9,   0x1fffde,
        0x7fffea,  0x3fffdd,  0x3fffde,   0xfffff0,  0x1fffdf,  0x3fffdf,   0x7fffeb,   0x7fffec,
        0x1fffe0,  0x1fffe1,  0x3fffe0,   0x1fffe2,  0x7fffed,  0x3fffe1,   0x7fffee,   0x7fffef,
        0xfffea,   0x3fffe2,  0x3fffe3,   0x3fffe4,  0x7ffff0,  0x3fffe5,   0x3fffe6,   0x7ffff1,
        0x3ffffe0, 0x3ffffe1, 0xfffeb,    0x7fff1,   0x3fffe7,  0x7ffff2,   0x3fffe8,   0x1ffffec,
        0x3ffffe2, 0x3ffffe3, 0x3ffffe4,  0x7ffffde, 0x7ffffdf, 0x3ffffe5,  0xfffff1,   0x1ffffed,
        0x7fff2,   0x1fffe3,  0x3ffffe6,  0x7ffffe0, 0x7ffffe1, 0x3ffffe7,  0x7ffffe2,  0xfffff2,
        0x1fffe4,  0x1fffe5,  0x3ffffe8,  0x3ffffe9, 0xffffffd, 0x7ffffe3,  0x7ffffe4,  0x7ffffe5,
        0xfffec,   0xfffff3,  0xfffed,    0x1fffe6,  0x3fffe9,  0x1fffe7,   0x1fffe8,   0x7ffff3,
        0x3fffea,  0x3fffeb,  0x1ffffee,  0x1ffffef, 0xfffff4,  0xfffff5,   0x3ffffea,  0x7ffff4,
        0x3ffffeb, 0x7ffffe6, 0x3ffffec,  0x3ffffed, 0x7ffffe7, 0x7ffffe8,  0x7ffffe9,  0x7ffffea,
        0x7ffffeb, 0xffffffe, 0x7ffffec,  0x7ffffed, 0x7ffffee, 0x7ffffef,  0x7fffff0,  0x3ffffee,
    };

    const lengths = [256]u5{
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
        28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        6,  10, 10, 12, 13, 6,  8,  11, 10, 10, 8,  11, 8,  6,  6,  6,
        5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8,  15, 6,  12, 10,
        13, 6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
        7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8,  13, 19, 13, 14, 6,
        15, 5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
        6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7,  15, 11, 14, 13, 28,
        20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
        22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
        21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
        19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
        20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    };

    const eos_code: u32 = 0x3fffffff;
    const eos_len: u5 = 30;

    /// Encodes data using Huffman coding.
    pub fn encode(data: []const u8, allocator: Allocator) ![]u8 {
        var result = std.ArrayList(u8).empty;
        errdefer result.deinit(allocator);

        var bit_buffer: u64 = 0;
        var bit_count: u8 = 0;

        for (data) |byte| {
            const code = codes[byte];
            const len = lengths[byte];

            bit_buffer = (bit_buffer << len) | code;
            bit_count += len;

            while (bit_count >= 8) {
                bit_count -= 8;
                const shift: std.math.Log2Int(u64) = @intCast(bit_count);
                try result.append(allocator, @intCast((bit_buffer >> shift) & 0xFF));
            }
        }

        // Pad with EOS prefix bits if needed
        if (bit_count > 0) {
            const pad_bits: std.math.Log2Int(u64) = @intCast(8 - bit_count);
            bit_buffer = (bit_buffer << pad_bits) | ((@as(u64, 1) << pad_bits) - 1);
            try result.append(allocator, @intCast(bit_buffer & 0xFF));
        }

        return result.toOwnedSlice(allocator);
    }

    /// Decodes Huffman-encoded data.
    pub fn decode(data: []const u8, allocator: Allocator) ![]u8 {
        var result = std.ArrayList(u8).empty;
        errdefer result.deinit(allocator);

        var bit_buffer: u64 = 0;
        var bit_count: u8 = 0;

        for (data) |byte| {
            if (bit_count > 56) return error.InvalidHuffmanEncoding;
            bit_buffer = (bit_buffer << 8) | byte;
            bit_count += 8;

            while (bit_count >= 5) {
                // Try to match a symbol
                var matched = false;
                for (0..256) |sym| {
                    const code = codes[sym];
                    const len = lengths[sym];

                    if (bit_count >= len) {
                        const code_len: std.math.Log2Int(u64) = @intCast(len);
                        const mask = (@as(u64, 1) << code_len) - 1;
                        const candidate_shift: std.math.Log2Int(u64) = @intCast(bit_count - len);
                        const candidate = (bit_buffer >> candidate_shift) & mask;
                        if (candidate == code) {
                            try result.append(allocator, @intCast(sym));
                            bit_count -= len;
                            matched = true;
                            break;
                        }
                    }
                }
                if (!matched) {
                    if (bit_count >= 30) return error.InvalidHuffmanEncoding;
                    break;
                }
            }
        }

        // Remaining bits should be EOS padding (all 1s)
        if (bit_count > 7) return error.InvalidHuffmanPadding;
        if (bit_count > 0) {
            const remaining: std.math.Log2Int(u64) = @intCast(bit_count);
            const mask = (@as(u64, 1) << remaining) - 1;
            if ((bit_buffer & mask) != mask) return error.InvalidHuffmanPadding;
        }

        return result.toOwnedSlice(allocator);
    }
};

/// How a literal header should be encoded (RFC 7541 Section 6.2).
pub const HeaderRepresentation = enum {
    /// Incremental indexing (0100 xxxx prefix). Adds to dynamic table.
    /// Use for stable headers that benefit from compression (e.g. :method, accept).
    incremental_indexing,

    /// Without indexing (0000 xxxx prefix). Never added to dynamic table.
    /// Use for volatile headers that change per request (e.g. date, cookie).
    without_indexing,

    /// Never indexed (0001 xxxx prefix). Must never be added to dynamic table.
    /// Use for security-sensitive headers that must not be compressed (e.g. authorization, set-cookie).
    /// Signals to intermediaries that the value must not be compressed.
    never_indexed,
};

/// Header entry for encoding.
pub const HeaderEntry = struct {
    name: []const u8,
    value: []const u8,
    /// How this header should be encoded. Defaults to incremental indexing.
    representation: HeaderRepresentation = .incremental_indexing,
};

/// Encodes a literal header field without indexing (RFC 7541 Section 6.2.2).
/// Prefix: 0000 (4-bit). Never added to dynamic table.
/// For indexed name: 0000 iiii + value. For literal name: 0000 0000 + name + value.
pub fn encodeHeaderWithoutIndexing(
    name_index: ?usize,
    name: []const u8,
    value: []const u8,
    allocator: Allocator,
    out: *std.ArrayList(u8),
) !void {
    if (name_index) |idx| {
        var buf: [10]u8 = undefined;
        const n = try encodeInteger(idx, 4, &buf);
        try out.appendSlice(allocator, buf[0..n]);
    } else {
        try out.append(allocator, 0x00); // 0000 0000
        try encodeString(name, true, allocator, out);
    }
    try encodeString(value, true, allocator, out);
}

/// Encodes a literal header field never indexed (RFC 7541 Section 6.2.3).
/// Prefix: 0001 (4-bit). Never added to dynamic table.
/// Signals to intermediaries that the value must never be compressed.
/// For indexed name: 0001 iiii + value. For literal name: 0001 0000 + name + value.
pub fn encodeHeaderNeverIndexed(
    name_index: ?usize,
    name: []const u8,
    value: []const u8,
    allocator: Allocator,
    out: *std.ArrayList(u8),
) !void {
    if (name_index) |idx| {
        var buf: [10]u8 = undefined;
        const n = try encodeInteger(idx, 4, &buf);
        buf[0] |= 0x10; // Set never-indexed prefix
        try out.appendSlice(allocator, buf[0..n]);
    } else {
        try out.append(allocator, 0x10); // 0001 0000
        try encodeString(name, true, allocator, out);
    }
    try encodeString(value, true, allocator, out);
}

/// Encodes a header block using HPACK.
pub fn encodeHeaders(
    ctx: *HPACKContext,
    headers: []const HeaderEntry,
    allocator: Allocator,
) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    if (ctx.pending_encoder_table_size) |table_size| {
        var buf: [10]u8 = undefined;
        const n = try encodeInteger(table_size, 5, &buf);
        buf[0] |= 0x20;
        try out.appendSlice(allocator, buf[0..n]);
    }

    for (headers) |header| {
        // Try to find in static table first
        if (header.representation == .incremental_indexing and
            StaticTable.findNameValue(header.name, header.value) != null)
        {
            const index = StaticTable.findNameValue(header.name, header.value).?;
            // Indexed header field (fully matched)
            var buf: [10]u8 = undefined;
            const n = try encodeInteger(index, 7, &buf);
            buf[0] |= 0x80; // Set indexed bit
            try out.appendSlice(allocator, buf[0..n]);
        } else {
            const name_index = StaticTable.findName(header.name);

            switch (header.representation) {
                .incremental_indexing => {
                    if (name_index) |idx| {
                        // Literal header with indexed name, incremental indexing
                        var buf: [10]u8 = undefined;
                        const n = try encodeInteger(idx, 6, &buf);
                        buf[0] |= 0x40;
                        try out.appendSlice(allocator, buf[0..n]);
                        try encodeString(header.value, true, allocator, &out);
                    } else {
                        // Literal header with literal name, incremental indexing
                        try out.append(allocator, 0x40);
                        try encodeString(header.name, true, allocator, &out);
                        try encodeString(header.value, true, allocator, &out);
                    }
                    try ctx.dynamic_table.add(header.name, header.value);
                },
                .without_indexing => {
                    try encodeHeaderWithoutIndexing(name_index, header.name, header.value, allocator, &out);
                },
                .never_indexed => {
                    try encodeHeaderNeverIndexed(name_index, header.name, header.value, allocator, &out);
                },
            }
        }
    }

    ctx.pending_encoder_table_size = null;
    return out.toOwnedSlice(allocator);
}

/// Decoded header entry.
pub const DecodedHeader = struct {
    name: []u8,
    value: []u8,
};

/// Decodes a header block using HPACK.
pub fn decodeHeaders(
    ctx: *HPACKContext,
    data: []const u8,
    allocator: Allocator,
) ![]DecodedHeader {
    return decodeHeadersWithLimit(ctx, data, allocator, 0);
}

/// Decodes HPACK while enforcing RFC header-list size accounting before
/// committing entries to the result or dynamic table. A limit of zero is
/// unlimited.
pub fn decodeHeadersWithLimit(
    ctx: *HPACKContext,
    data: []const u8,
    allocator: Allocator,
    max_header_list_size: u64,
) ![]DecodedHeader {
    var headers = std.ArrayList(DecodedHeader).empty;
    errdefer {
        for (headers.items) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        headers.deinit(allocator);
    }

    var offset: usize = 0;
    var header_list_size: u64 = 0;
    var saw_header_field = false;

    while (offset < data.len) {
        const first = data[offset];

        if (first & 0x80 != 0) {
            saw_header_field = true;
            // Indexed header field
            const idx_result = try decodeInteger(data[offset..], 7);
            offset += idx_result.len;

            const index = std.math.cast(usize, idx_result.value) orelse return error.InvalidIndex;
            const entry = ctx.getByIndex(index) orelse return error.InvalidIndex;
            try accountHeaderListSize(
                &header_list_size,
                entry.name.len,
                entry.value.len,
                max_header_list_size,
            );
            const name = try allocator.dupe(u8, entry.name);
            errdefer allocator.free(name);
            const value = try allocator.dupe(u8, entry.value);
            errdefer allocator.free(value);
            try headers.append(allocator, .{ .name = name, .value = value });
        } else if (first & 0x40 != 0) {
            saw_header_field = true;
            // Literal with incremental indexing
            const idx_result = try decodeInteger(data[offset..], 6);
            offset += idx_result.len;

            var name: []u8 = undefined;
            if (idx_result.value > 0) {
                const index = std.math.cast(usize, idx_result.value) orelse return error.InvalidIndex;
                const entry = ctx.getByIndex(index) orelse return error.InvalidIndex;
                name = try allocator.dupe(u8, entry.name);
            } else {
                const name_result = try decodeString(data[offset..], allocator);
                offset += name_result.len;
                name = name_result.value;
            }
            errdefer allocator.free(name);

            const value_result = try decodeString(data[offset..], allocator);
            errdefer allocator.free(value_result.value);
            offset += value_result.len;

            try accountHeaderListSize(
                &header_list_size,
                name.len,
                value_result.value.len,
                max_header_list_size,
            );
            try headers.ensureUnusedCapacity(allocator, 1);
            try ctx.dynamic_table.add(name, value_result.value);
            headers.appendAssumeCapacity(.{ .name = name, .value = value_result.value });
        } else if (first & 0x20 != 0) {
            // Dynamic table size update
            if (saw_header_field) return error.InvalidDynamicTableSize;
            const size_result = try decodeInteger(data[offset..], 5);
            offset += size_result.len;
            if (size_result.value > @as(u64, ctx.max_allowed_table_size) or
                size_result.value > std.math.maxInt(usize))
            {
                return error.InvalidDynamicTableSize;
            }
            ctx.dynamic_table.setMaxSize(@intCast(size_result.value));
        } else {
            saw_header_field = true;
            // Literal without indexing or never indexed
            const prefix_bits: u3 = if (first & 0x10 != 0) 4 else 4;
            const idx_result = try decodeInteger(data[offset..], prefix_bits);
            offset += idx_result.len;

            var name: []u8 = undefined;
            if (idx_result.value > 0) {
                const index = std.math.cast(usize, idx_result.value) orelse return error.InvalidIndex;
                const entry = ctx.getByIndex(index) orelse return error.InvalidIndex;
                name = try allocator.dupe(u8, entry.name);
            } else {
                const name_result = try decodeString(data[offset..], allocator);
                offset += name_result.len;
                name = name_result.value;
            }
            errdefer allocator.free(name);

            const value_result = try decodeString(data[offset..], allocator);
            errdefer allocator.free(value_result.value);
            offset += value_result.len;

            try accountHeaderListSize(
                &header_list_size,
                name.len,
                value_result.value.len,
                max_header_list_size,
            );
            try headers.append(allocator, .{ .name = name, .value = value_result.value });
        }
    }

    return headers.toOwnedSlice(allocator);
}

fn accountHeaderListSize(total: *u64, name_len: usize, value_len: usize, limit: u64) !void {
    const field_size = std.math.add(
        u64,
        @as(u64, name_len),
        @as(u64, value_len),
    ) catch return error.HeaderListTooLarge;
    const accounted = std.math.add(u64, field_size, 32) catch
        return error.HeaderListTooLarge;
    total.* = std.math.add(
        u64,
        total.*,
        accounted,
    ) catch return error.HeaderListTooLarge;
    if (limit > 0 and total.* > limit) return error.HeaderListTooLarge;
}

test "HPACK integer encoding" {
    var buf: [10]u8 = undefined;

    // Test small values
    const n1 = try encodeInteger(10, 5, &buf);
    try std.testing.expectEqual(@as(usize, 1), n1);
    try std.testing.expectEqual(@as(u8, 10), buf[0]);

    // Test value requiring continuation
    const n2 = try encodeInteger(1337, 5, &buf);
    try std.testing.expectEqual(@as(usize, 3), n2);
}

test "HPACK integer decoding" {
    // Small value
    const data1 = [_]u8{10};
    const result1 = try decodeInteger(&data1, 5);
    try std.testing.expectEqual(@as(u64, 10), result1.value);
    try std.testing.expectEqual(@as(usize, 1), result1.len);

    // Value 1337 encoded with 5-bit prefix
    const data2 = [_]u8{ 31, 154, 10 };
    const result2 = try decodeInteger(&data2, 5);
    try std.testing.expectEqual(@as(u64, 1337), result2.value);
    try std.testing.expectEqual(@as(usize, 3), result2.len);
}

test "HPACK malformed arithmetic returns errors without panics" {
    var output: [16]u8 = undefined;
    try std.testing.expectError(error.InvalidPrefixBits, encodeInteger(1, 0, &output));
    try std.testing.expectError(error.InvalidPrefixBits, decodeInteger(&.{0}, 9));

    var continuation: [16]u8 = [_]u8{0xff} ** 16;
    continuation[0] = 0x7f;
    try std.testing.expectError(error.IntegerOverflow, decodeInteger(&continuation, 7));

    var oversized: [12]u8 = undefined;
    const length_bytes = try encodeInteger(std.math.maxInt(u64), 7, &oversized);
    oversized[0] |= 0x80;
    try std.testing.expectError(
        error.StringLengthOverflow,
        decodeString(oversized[0..length_bytes], std.testing.allocator),
    );

    var random_state: u64 = 0xe7037ed1a0b428db;
    var data: [64]u8 = undefined;
    for (0..200) |_| {
        for (&data) |*byte| {
            random_state ^= random_state << 13;
            random_state ^= random_state >> 7;
            random_state ^= random_state << 17;
            byte.* = @truncate(random_state);
        }
        if (HuffmanCodec.decode(&data, std.testing.allocator)) |decoded| {
            std.testing.allocator.free(decoded);
        } else |_| {}
    }
}

test "HPACK static table lookup" {
    const entry = StaticTable.get(2).?;
    try std.testing.expectEqualStrings(":method", entry.name);
    try std.testing.expectEqualStrings("GET", entry.value);

    const idx = StaticTable.findNameValue(":method", "POST").?;
    try std.testing.expectEqual(@as(usize, 3), idx);
}

test "HPACK dynamic table" {
    const allocator = std.testing.allocator;
    var table = DynamicTable.init(allocator);
    defer table.deinit();

    try table.add("custom-header", "custom-value");
    try std.testing.expectEqual(@as(usize, 1), table.len());

    const entry = table.get(0).?;
    try std.testing.expectEqualStrings("custom-header", entry.name);
    try std.testing.expectEqualStrings("custom-value", entry.value);
}

test "HPACK context combined lookup" {
    const allocator = std.testing.allocator;
    var ctx = HPACKContext.init(allocator);
    defer ctx.deinit();

    // Static table lookup
    const static_entry = ctx.getByIndex(2).?;
    try std.testing.expectEqualStrings(":method", static_entry.name);

    // Add to dynamic table
    try ctx.dynamic_table.add("x-custom", "value");

    // Dynamic table lookup (index 62 = first dynamic entry)
    const dynamic_entry = ctx.getByIndex(62).?;
    try std.testing.expectEqualStrings("x-custom", dynamic_entry.name);
}

test "HPACK decode enforces header list limit without leaking partial entries" {
    var encoder = HPACKContext.init(std.testing.allocator);
    defer encoder.deinit();
    const fields = [_]HeaderEntry{
        .{ .name = ":status", .value = "200", .representation = .without_indexing },
        .{ .name = "x-large", .value = "0123456789", .representation = .without_indexing },
    };
    const encoded = try encodeHeaders(&encoder, &fields, std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    var limited_decoder = HPACKContext.init(std.testing.allocator);
    defer limited_decoder.deinit();
    try std.testing.expectError(
        error.HeaderListTooLarge,
        decodeHeadersWithLimit(&limited_decoder, encoded, std.testing.allocator, 40),
    );

    const Case = struct {
        fn run(allocator: Allocator, wire: []const u8) !void {
            var decoder = HPACKContext.init(allocator);
            defer decoder.deinit();
            const decoded = try decodeHeadersWithLimit(&decoder, wire, allocator, 0);
            defer {
                for (decoded) |header| {
                    allocator.free(header.name);
                    allocator.free(header.value);
                }
                allocator.free(decoded);
            }
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Case.run,
        .{encoded},
    );
}

test "HPACK decoder rejects table updates above local advertised maximum" {
    var context = HPACKContext.initWithTableSize(std.testing.allocator, 4096);
    defer context.deinit();
    var bytes: [16]u8 = undefined;
    const len = try encodeInteger(8192, 5, &bytes);
    bytes[0] |= 0x20;
    try std.testing.expectError(
        error.InvalidDynamicTableSize,
        decodeHeaders(&context, bytes[0..len], std.testing.allocator),
    );
    try std.testing.expectEqual(@as(usize, 4096), context.dynamic_table.max_size);
}

test "HPACK incremental decode allocation failure does not mutate decoder table" {
    var encoder = HPACKContext.init(std.testing.allocator);
    defer encoder.deinit();
    const fields = [_]HeaderEntry{.{
        .name = "x-transactional",
        .value = "value",
        .representation = .incremental_indexing,
    }};
    const encoded = try encodeHeaders(&encoder, &fields, std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    const Case = struct {
        fn run(allocator: Allocator, wire: []const u8) !void {
            var decoder = HPACKContext.init(allocator);
            defer decoder.deinit();
            const decoded = try decodeHeaders(&decoder, wire, allocator);
            defer {
                for (decoded) |header| {
                    allocator.free(header.name);
                    allocator.free(header.value);
                }
                allocator.free(decoded);
            }
            try std.testing.expectEqual(@as(usize, 1), decoder.dynamic_table.len());
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Case.run,
        .{encoded},
    );
}

test "Huffman encode/decode roundtrip" {
    const allocator = std.testing.allocator;

    const original = "www.httpbun.com";
    const encoded = try HuffmanCodec.encode(original, allocator);
    defer allocator.free(encoded);

    const decoded = try HuffmanCodec.decode(encoded, allocator);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings(original, decoded);
}

test "encode without indexing - indexed name" {
    const allocator = std.testing.allocator;

    // "authorization" is static table index 23, value ""
    const headers = [_]HeaderEntry{
        .{ .name = "authorization", .value = "Bearer secret123", .representation = .without_indexing },
    };

    var ctx = HPACKContext.init(allocator);
    defer ctx.deinit();

    const encoded = try encodeHeaders(&ctx, &headers, allocator);
    defer allocator.free(encoded);

    // Should NOT be added to dynamic table
    try std.testing.expectEqual(@as(usize, 0), ctx.dynamic_table.len());

    // First byte: 0x0F (4-bit prefix, value 15 = min(23, 15)), second byte: 0x08 (23-15=8)
    try std.testing.expectEqual(@as(u8, 0x0F), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0x08), encoded[1]);

    // Should be decodable
    var ctx2 = HPACKContext.init(allocator);
    defer ctx2.deinit();
    const decoded = try decodeHeaders(&ctx2, encoded, allocator);
    defer {
        for (decoded) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(decoded);
    }
    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqualStrings("authorization", decoded[0].name);
    try std.testing.expectEqualStrings("Bearer secret123", decoded[0].value);
}

test "encode without indexing - literal name" {
    const allocator = std.testing.allocator;

    const headers = [_]HeaderEntry{
        .{ .name = "x-custom-header", .value = "some-value", .representation = .without_indexing },
    };

    var ctx = HPACKContext.init(allocator);
    defer ctx.deinit();

    const encoded = try encodeHeaders(&ctx, &headers, allocator);
    defer allocator.free(encoded);

    // Should NOT be added to dynamic table
    try std.testing.expectEqual(@as(usize, 0), ctx.dynamic_table.len());

    // First byte should be 0x00 (0000 0000 = literal name without indexing)
    try std.testing.expectEqual(@as(u8, 0x00), encoded[0]);

    // Should be decodable
    var ctx2 = HPACKContext.init(allocator);
    defer ctx2.deinit();
    const decoded = try decodeHeaders(&ctx2, encoded, allocator);
    defer {
        for (decoded) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(decoded);
    }
    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqualStrings("x-custom-header", decoded[0].name);
    try std.testing.expectEqualStrings("some-value", decoded[0].value);
}

test "encode never indexed - indexed name" {
    const allocator = std.testing.allocator;

    // "set-cookie" is static table index 55
    const headers = [_]HeaderEntry{
        .{ .name = "set-cookie", .value = "session=abc123", .representation = .never_indexed },
    };

    var ctx = HPACKContext.init(allocator);
    defer ctx.deinit();

    const encoded = try encodeHeaders(&ctx, &headers, allocator);
    defer allocator.free(encoded);

    // Should NOT be added to dynamic table
    try std.testing.expectEqual(@as(usize, 0), ctx.dynamic_table.len());

    // First byte: 0x1F (0001 prefix + value 15), second byte: 0x28 (55-15=40)
    try std.testing.expectEqual(@as(u8, 0x1F), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0x28), encoded[1]);

    // Should be decodable
    var ctx2 = HPACKContext.init(allocator);
    defer ctx2.deinit();
    const decoded = try decodeHeaders(&ctx2, encoded, allocator);
    defer {
        for (decoded) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(decoded);
    }
    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqualStrings("set-cookie", decoded[0].name);
    try std.testing.expectEqualStrings("session=abc123", decoded[0].value);
}

test "encode never indexed - literal name" {
    const allocator = std.testing.allocator;

    const headers = [_]HeaderEntry{
        .{ .name = "x-secret", .value = "top-secret-data", .representation = .never_indexed },
    };

    var ctx = HPACKContext.init(allocator);
    defer ctx.deinit();

    const encoded = try encodeHeaders(&ctx, &headers, allocator);
    defer allocator.free(encoded);

    // Should NOT be added to dynamic table
    try std.testing.expectEqual(@as(usize, 0), ctx.dynamic_table.len());

    // First byte should be 0x10 (0001 0000 = literal name never indexed)
    try std.testing.expectEqual(@as(u8, 0x10), encoded[0]);

    // Should be decodable
    var ctx2 = HPACKContext.init(allocator);
    defer ctx2.deinit();
    const decoded = try decodeHeaders(&ctx2, encoded, allocator);
    defer {
        for (decoded) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(decoded);
    }
    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqualStrings("x-secret", decoded[0].name);
    try std.testing.expectEqualStrings("top-secret-data", decoded[0].value);
}

test "mixed representations in header block" {
    const allocator = std.testing.allocator;

    const headers = [_]HeaderEntry{
        // Incremental indexing (default) - should add to dynamic table
        .{ .name = ":method", .value = "GET" },
        // Without indexing - should NOT add to dynamic table
        .{ .name = "authorization", .value = "Bearer token", .representation = .without_indexing },
        // Never indexed - should NOT add to dynamic table
        .{ .name = "cookie", .value = "session=xyz", .representation = .never_indexed },
        // Another incremental - should add to dynamic table
        .{ .name = "content-type", .value = "text/html" },
    };

    var ctx = HPACKContext.init(allocator);
    defer ctx.deinit();

    const encoded = try encodeHeaders(&ctx, &headers, allocator);
    defer allocator.free(encoded);

    // Only 2 entries should be in dynamic table (the incremental ones that didn't match static table exactly)
    // ":method" "GET" matches static table index 2 exactly, so it's encoded as indexed (no dynamic table add)
    // "content-type" "text/html" doesn't match static table value, so it gets added
    try std.testing.expectEqual(@as(usize, 1), ctx.dynamic_table.len());

    // Roundtrip decode
    var ctx2 = HPACKContext.init(allocator);
    defer ctx2.deinit();
    const decoded = try decodeHeaders(&ctx2, encoded, allocator);
    defer {
        for (decoded) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(decoded);
    }
    try std.testing.expectEqual(@as(usize, 4), decoded.len);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqualStrings("authorization", decoded[1].name);
    try std.testing.expectEqualStrings("Bearer token", decoded[1].value);
    try std.testing.expectEqualStrings("cookie", decoded[2].name);
    try std.testing.expectEqualStrings("session=xyz", decoded[2].value);
    try std.testing.expectEqualStrings("content-type", decoded[3].name);
    try std.testing.expectEqualStrings("text/html", decoded[3].value);
}

test "HPACK table size update is only accepted at block start" {
    var ctx = HPACKContext.init(std.testing.allocator);
    defer ctx.deinit();
    const encoded = [_]u8{ 0x82, 0x20 };
    try std.testing.expectError(
        error.InvalidDynamicTableSize,
        decodeHeaders(&ctx, &encoded, std.testing.allocator),
    );
}

test "HPACK encoder emits queued table update at next block start" {
    var encoder = HPACKContext.init(std.testing.allocator);
    defer encoder.deinit();
    var decoder = HPACKContext.init(std.testing.allocator);
    defer decoder.deinit();

    encoder.setEncoderTableSize(128);
    const fields = [_]HeaderEntry{.{ .name = ":method", .value = "GET" }};
    const encoded = try encodeHeaders(&encoder, &fields, std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    try std.testing.expect(encoded.len >= 2);
    try std.testing.expect((encoded[0] & 0xe0) == 0x20);

    const decoded = try decodeHeaders(&decoder, encoded, std.testing.allocator);
    defer {
        for (decoded) |field| {
            std.testing.allocator.free(field.name);
            std.testing.allocator.free(field.value);
        }
        std.testing.allocator.free(decoded);
    }
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqual(@as(usize, 128), decoder.dynamic_table.max_size);
}
