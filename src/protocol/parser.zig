//! Incremental HTTP Message Parser for httpx.zig
//!
//! State-machine based parser for HTTP/1.x messages supporting:
//!
//! - Incremental parsing (feed data as it arrives)
//! - Request and response parsing
//! - Chunked transfer encoding
//! - Header limits for security
//! - Cross-platform compatible

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const types = @import("../core/types.zig");
const Headers = @import("../core/headers.zig").Headers;
const Status = @import("../core/status.zig").Status;

/// Parser state machine states.
pub const ParserState = enum {
    start,
    request_line,
    status_line,
    headers,
    body,
    chunk_size,
    chunk_data,
    chunk_crlf,
    chunk_trailer,
    complete,
    err,
};

/// Parser mode - request or response.
pub const ParserMode = enum {
    request,
    response,
};

pub const BodySink = struct {
    context: *anyopaque,
    writeFn: *const fn (*anyopaque, []const u8) anyerror!usize,
    stop_after_write: bool = false,

    pub fn write(self: *BodySink, data: []const u8) !usize {
        return self.writeFn(self.context, data);
    }
};

/// Incremental HTTP message parser.
pub const Parser = struct {
    allocator: Allocator,
    state: ParserState = .start,
    mode: ParserMode = .request,
    method: ?types.Method = null,
    path: ?[]const u8 = null,
    version: types.Version = .HTTP_1_1,
    status_code: ?u16 = null,
    headers: Headers,
    trailers: Headers,
    body_buffer: std.ArrayList(u8) = .empty,
    content_length: ?u64 = null,
    chunked: bool = false,
    current_chunk_size: u64 = 0,
    bytes_read: u64 = 0,
    body_bytes: u64 = 0,
    chunk_crlf_read: u2 = 0,
    line_buffer: std.ArrayList(u8) = .empty,
    max_header_size: usize = 8192,
    max_headers: usize = 100,
    header_bytes: usize = 0,
    header_count: usize = 0,
    /// When false, the parser will not enter body state for responses.
    /// Used for HEAD responses which have no body.
    expect_body: bool = true,
    /// Maximum body size in bytes. 0 means unlimited. Prevents memory exhaustion.
    max_body_size: u64 = 0,
    /// Whether Connection: close was seen.
    connection_close: bool = false,
    /// Whether Connection: keep-alive was seen.
    connection_keep_alive: bool = false,
    /// Whether Transfer-Encoding header was seen (for conflict detection).
    transfer_encoding_seen: bool = false,

    const Self = @This();

    /// Creates a new parser instance.
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .headers = Headers.init(allocator),
            .trailers = Headers.init(allocator),
        };
    }

    /// Creates a parser for parsing responses.
    pub fn initResponse(allocator: Allocator) Self {
        var p = init(allocator);
        p.mode = .response;
        p.state = .status_line;
        return p;
    }

    /// Releases all allocated memory.
    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        self.trailers.deinit();
        self.body_buffer.deinit(self.allocator);
        self.line_buffer.deinit(self.allocator);
        if (self.path) |p| self.allocator.free(p);
    }

    /// Finalizes parsing when the underlying stream has reached EOF.
    ///
    /// For HTTP/1.x responses with neither `Content-Length` nor `Transfer-Encoding: chunked`,
    /// the body is delimited by connection close. In that case, reaching EOF means the
    /// message is complete.
    pub fn finishEof(self: *Self) void {
        if (self.state == .body and self.mode == .response and self.content_length == null and !self.chunked) {
            self.state = .complete;
        } else if (self.state != .complete) {
            self.state = .err;
        }
    }

    /// Feeds data to the parser, returning the number of bytes consumed.
    pub fn feed(self: *Self, data: []const u8) !usize {
        var sink = BodySink{
            .context = self,
            .writeFn = struct {
                fn write(context: *anyopaque, body: []const u8) !usize {
                    const parser: *Parser = @ptrCast(@alignCast(context));
                    try parser.body_buffer.appendSlice(parser.allocator, body);
                    return body.len;
                }
            }.write,
        };
        return self.feedTo(data, &sink);
    }

    /// Feeds data while delivering decoded body bytes to a bounded sink.
    /// The sink may accept fewer bytes than supplied; unconsumed input remains
    /// with the caller. Returning zero pauses parsing without spinning.
    pub fn feedTo(self: *Self, data: []const u8, sink: *BodySink) !usize {
        var consumed: usize = 0;

        while (consumed < data.len and self.state != .complete and self.state != .err) {
            const remaining = data[consumed..];
            const previous_state = self.state;
            const step = switch (self.state) {
                .start => self.parseStart(remaining),
                .request_line => try self.parseRequestLine(remaining),
                .status_line => try self.parseStatusLine(remaining),
                .headers => try self.parseHeaders(remaining),
                .body => try self.parseBody(remaining, sink),
                .chunk_size => try self.parseChunkSize(remaining),
                .chunk_data => try self.parseChunkData(remaining, sink),
                .chunk_crlf => try self.parseChunkCrlf(remaining),
                .chunk_trailer => try self.parseChunkTrailer(remaining),
                .complete, .err => break,
            };
            if (step == 0) {
                if (self.state == previous_state) break;
                continue;
            }
            consumed += step;
            if (sink.stop_after_write and
                (previous_state == .body or previous_state == .chunk_data))
            {
                break;
            }
        }

        return consumed;
    }

    /// Returns true if parsing is complete.
    pub fn isComplete(self: *const Self) bool {
        return self.state == .complete;
    }

    /// Returns true if parsing encountered an error.
    pub fn isError(self: *const Self) bool {
        return self.state == .err;
    }

    /// Returns the parsed body.
    pub fn getBody(self: *const Self) []const u8 {
        return self.body_buffer.items;
    }

    /// Returns the parsed status.
    pub fn getStatus(self: *const Self) ?Status {
        if (self.status_code) |code| {
            return Status.fromCode(code);
        }
        return null;
    }

    /// Resets the parser for reuse.
    pub fn reset(self: *Self) void {
        self.state = .start;
        self.method = null;
        if (self.path) |p| {
            self.allocator.free(p);
            self.path = null;
        }
        self.status_code = null;
        self.headers.clear();
        self.trailers.clear();
        self.body_buffer.clearRetainingCapacity();
        self.line_buffer.clearRetainingCapacity();
        self.content_length = null;
        self.chunked = false;
        self.current_chunk_size = 0;
        self.bytes_read = 0;
        self.body_bytes = 0;
        self.chunk_crlf_read = 0;
        self.header_bytes = 0;
        self.header_count = 0;
        self.connection_close = false;
        self.connection_keep_alive = false;
        self.transfer_encoding_seen = false;
    }

    /// Returns whether the connection should be kept alive based on parsed headers
    /// and HTTP version. Implements RFC 7230 Section 6.3 semantics.
    pub fn isKeepAlive(self: *const Self) bool {
        if (self.connection_close) return false;
        if (self.connection_keep_alive) return true;
        // HTTP/1.1 defaults to keep-alive; HTTP/1.0 defaults to close.
        return self.version == .HTTP_1_1;
    }

    fn checkLineBufferLimit(self: *Self) !void {
        if (self.line_buffer.items.len > self.max_header_size) {
            self.state = .err;
            return error.HeaderTooLarge;
        }
    }

    fn bumpHeaderBytes(self: *Self, line_len: usize) !void {
        // Account for CRLF too.
        self.header_bytes += line_len + 2;
        if (self.header_bytes > self.max_header_size) {
            self.state = .err;
            return error.HeaderTooLarge;
        }
    }

    fn parseStart(self: *Self, data: []const u8) usize {
        if (data.len == 0) return 0;

        if (self.mode == .response) {
            self.state = .status_line;
        } else {
            self.state = .request_line;
        }
        return 0;
    }

    fn parseRequestLine(self: *Self, data: []const u8) !usize {
        const line_end = mem.indexOf(u8, data, "\r\n") orelse {
            try self.line_buffer.appendSlice(self.allocator, data);
            try self.checkLineBufferLimit();
            return data.len;
        };

        const line = if (self.line_buffer.items.len > 0) blk: {
            try self.line_buffer.appendSlice(self.allocator, data[0..line_end]);
            break :blk self.line_buffer.items;
        } else data[0..line_end];

        var parts = mem.splitScalar(u8, line, ' ');

        const method_str = parts.next() orelse {
            self.state = .err;
            return line_end + 2;
        };
        self.method = types.Method.fromString(method_str) orelse .CUSTOM;

        const path = parts.next() orelse {
            self.state = .err;
            return line_end + 2;
        };
        self.path = try self.allocator.dupe(u8, path);

        const version_str = parts.next() orelse {
            self.state = .err;
            return line_end + 2;
        };
        self.version = types.Version.fromString(version_str) orelse .HTTP_1_1;

        try self.bumpHeaderBytes(line.len);

        self.line_buffer.clearRetainingCapacity();
        self.state = .headers;
        return line_end + 2;
    }

    fn parseStatusLine(self: *Self, data: []const u8) !usize {
        const line_end = mem.indexOf(u8, data, "\r\n") orelse {
            try self.line_buffer.appendSlice(self.allocator, data);
            try self.checkLineBufferLimit();
            return data.len;
        };

        const line = if (self.line_buffer.items.len > 0) blk: {
            try self.line_buffer.appendSlice(self.allocator, data[0..line_end]);
            break :blk self.line_buffer.items;
        } else data[0..line_end];

        var parts = mem.splitScalar(u8, line, ' ');

        const version_str = parts.next() orelse {
            self.state = .err;
            return line_end + 2;
        };
        self.version = types.Version.fromString(version_str) orelse .HTTP_1_1;

        const status_str = parts.next() orelse {
            self.state = .err;
            return line_end + 2;
        };
        self.status_code = std.fmt.parseInt(u16, status_str, 10) catch {
            self.state = .err;
            return line_end + 2;
        };

        try self.bumpHeaderBytes(line.len);

        self.line_buffer.clearRetainingCapacity();
        self.state = .headers;
        return line_end + 2;
    }

    fn parseHeaders(self: *Self, data: []const u8) !usize {
        const line_end = mem.indexOf(u8, data, "\r\n") orelse {
            try self.line_buffer.appendSlice(self.allocator, data);
            try self.checkLineBufferLimit();
            return data.len;
        };

        const line = if (self.line_buffer.items.len > 0) blk: {
            try self.line_buffer.appendSlice(self.allocator, data[0..line_end]);
            break :blk self.line_buffer.items;
        } else data[0..line_end];

        if (line.len == 0) {
            self.line_buffer.clearRetainingCapacity();
            try self.bumpHeaderBytes(0);
            try self.determineBodyState();
            return line_end + 2;
        }

        try self.bumpHeaderBytes(line.len);

        if (mem.indexOf(u8, line, ":")) |sep| {
            if (self.header_count >= self.max_headers) {
                self.state = .err;
                return error.TooManyHeaders;
            }
            const name = mem.trim(u8, line[0..sep], " \t");
            const value = mem.trim(u8, line[sep + 1 ..], " \t");
            try self.headers.append(name, value);
            self.header_count += 1;

            if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                if (self.transfer_encoding_seen) {
                    self.state = .err;
                    return error.ConflictingFramingHeaders;
                } else {
                    // Content-Length may be a comma-separated list of integers,
                    // all of which must be identical.
                    var cl_iter = std.mem.splitScalar(u8, value, ',');
                    while (cl_iter.next()) |cl_part| {
                        const trimmed = std.mem.trim(u8, cl_part, " \t");
                        if (trimmed.len == 0) continue;
                        const cl = std.fmt.parseInt(u64, trimmed, 10) catch {
                            self.state = .err;
                            return error.InvalidContentLength;
                        };
                        if (self.content_length) |existing| {
                            if (existing != cl) {
                                // RFC 7230: conflicting Content-Length values are an error.
                                self.state = .err;
                                return error.InvalidContentLength;
                            }
                        } else {
                            self.content_length = cl;
                        }
                    }
                }
            } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
                if (self.transfer_encoding_seen) {
                    self.state = .err;
                    return error.InvalidChunkEncoding;
                }
                // RFC 7230 3.3.1: Transfer-Encoding is not allowed in HTTP/1.0.
                if (self.version == .HTTP_1_0) {
                    self.state = .err;
                    return error.InvalidChunkEncoding;
                }
                var codings = std.mem.splitScalar(u8, value, ',');
                const first = std.mem.trim(u8, codings.next() orelse "", " \t");
                if (!std.ascii.eqlIgnoreCase(first, "chunked") or codings.next() != null) {
                    self.state = .err;
                    return error.InvalidChunkEncoding;
                }
                self.chunked = true;
                self.transfer_encoding_seen = true;
                if (self.content_length != null) {
                    self.state = .err;
                    return error.ConflictingFramingHeaders;
                }
            } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
                if (std.ascii.indexOfIgnoreCase(value, "close") != null) {
                    self.connection_close = true;
                }
                if (std.ascii.indexOfIgnoreCase(value, "keep-alive") != null) {
                    self.connection_keep_alive = true;
                }
            }
        } else {
            self.state = .err;
            return error.InvalidHeader;
        }

        self.line_buffer.clearRetainingCapacity();
        return line_end + 2;
    }

    fn noBodyByStatus(self: *const Self) bool {
        if (self.status_code) |code| {
            return (code >= 100 and code < 200) or code == 204 or code == 304;
        }
        return false;
    }

    fn determineBodyState(self: *Self) !void {
        if (!self.expect_body or self.noBodyByStatus()) {
            self.state = .complete;
            return;
        }
        if (self.chunked) {
            self.state = .chunk_size;
        } else if (self.content_length) |len| {
            if (self.max_body_size > 0 and len > self.max_body_size) {
                self.state = .err;
                return error.BodyTooLarge;
            }
            if (len > 0) {
                self.state = .body;
            } else {
                self.state = .complete;
            }
        } else if (self.mode == .response) {
            self.state = .body;
        } else {
            self.state = .complete;
        }
    }

    fn parseBody(self: *Self, data: []const u8, sink: *BodySink) !usize {
        if (self.content_length) |len| {
            const remaining = len - self.bytes_read;
            const to_read: usize = @intCast(@min(@as(u64, data.len), remaining));
            if (self.max_body_size > 0 and self.body_bytes + to_read > self.max_body_size) {
                self.state = .err;
                return error.BodyTooLarge;
            }
            const written = try sink.write(data[0..to_read]);
            if (written > to_read) return error.InvalidSinkProgress;
            self.bytes_read += written;
            self.body_bytes += written;

            if (self.bytes_read >= len) {
                self.state = .complete;
            }
            return written;
        }

        var to_read = data.len;
        if (self.max_body_size > 0) {
            const remaining = self.max_body_size -| self.body_bytes;
            if (remaining == 0 and data.len > 0) {
                self.state = .err;
                return error.BodyTooLarge;
            }
            to_read = @intCast(@min(@as(u64, data.len), remaining));
        }
        const written = try sink.write(data[0..to_read]);
        if (written > to_read) return error.InvalidSinkProgress;
        self.body_bytes += written;
        if (written < data.len and self.max_body_size > 0 and self.body_bytes == self.max_body_size) {
            self.state = .err;
            return error.BodyTooLarge;
        }
        return written;
    }

    fn parseChunkSize(self: *Self, data: []const u8) !usize {
        const line_end = mem.indexOf(u8, data, "\r\n") orelse {
            try self.line_buffer.appendSlice(self.allocator, data);
            try self.checkLineBufferLimit();
            return data.len;
        };

        const line = if (self.line_buffer.items.len > 0) blk: {
            try self.line_buffer.appendSlice(self.allocator, data[0..line_end]);
            break :blk self.line_buffer.items;
        } else data[0..line_end];

        const size_part = if (mem.indexOfScalar(u8, line, ';')) |semi|
            mem.trim(u8, line[0..semi], " \t")
        else
            mem.trim(u8, line, " \t");

        if (size_part.len == 0) {
            self.state = .err;
            return error.InvalidChunkEncoding;
        }
        self.current_chunk_size = std.fmt.parseInt(u64, size_part, 16) catch {
            self.state = .err;
            return error.InvalidChunkEncoding;
        };

        self.line_buffer.clearRetainingCapacity();
        self.bytes_read = 0;
        self.chunk_crlf_read = 0;

        if (self.current_chunk_size == 0) {
            self.state = .chunk_trailer;
        } else {
            self.state = .chunk_data;
        }

        return line_end + 2;
    }

    fn parseChunkData(self: *Self, data: []const u8, sink: *BodySink) !usize {
        const remaining = self.current_chunk_size - self.bytes_read;
        const to_read: usize = @intCast(@min(@as(u64, data.len), remaining));

        if (self.max_body_size > 0 and self.body_bytes + to_read > self.max_body_size) {
            self.state = .err;
            return error.BodyTooLarge;
        }
        const written = try sink.write(data[0..to_read]);
        if (written > to_read) return error.InvalidSinkProgress;
        self.bytes_read += written;
        self.body_bytes += written;

        if (self.bytes_read >= self.current_chunk_size) {
            self.state = .chunk_crlf;
        }

        return written;
    }

    fn parseChunkCrlf(self: *Self, data: []const u8) !usize {
        if (data.len == 0) return 0;

        var consumed: usize = 0;
        while (consumed < data.len and self.chunk_crlf_read < 2) {
            const b = data[consumed];
            switch (self.chunk_crlf_read) {
                0 => if (b != '\r') {
                    self.state = .err;
                    return error.InvalidChunkEncoding;
                },
                1 => if (b != '\n') {
                    self.state = .err;
                    return error.InvalidChunkEncoding;
                },
                else => {},
            }
            self.chunk_crlf_read += 1;
            consumed += 1;
        }

        if (self.chunk_crlf_read == 2) {
            self.chunk_crlf_read = 0;
            self.state = .chunk_size;
        }

        return consumed;
    }

    fn parseChunkTrailer(self: *Self, data: []const u8) !usize {
        const line_end = mem.indexOf(u8, data, "\r\n") orelse {
            try self.line_buffer.appendSlice(self.allocator, data);
            try self.checkLineBufferLimit();
            return data.len;
        };

        const line = if (self.line_buffer.items.len > 0) blk: {
            try self.line_buffer.appendSlice(self.allocator, data[0..line_end]);
            break :blk self.line_buffer.items;
        } else data[0..line_end];

        if (line.len == 0) {
            self.line_buffer.clearRetainingCapacity();
            self.state = .complete;
            return line_end + 2;
        }

        try self.bumpHeaderBytes(line.len);
        const sep = mem.indexOfScalar(u8, line, ':') orelse {
            self.state = .err;
            return error.InvalidHeader;
        };
        const name = mem.trim(u8, line[0..sep], " \t");
        const value = mem.trim(u8, line[sep + 1 ..], " \t");
        if (name.len == 0 or
            std.ascii.eqlIgnoreCase(name, "content-length") or
            std.ascii.eqlIgnoreCase(name, "transfer-encoding"))
        {
            self.state = .err;
            return error.InvalidHeader;
        }
        if (self.header_count >= self.max_headers) {
            self.state = .err;
            return error.TooManyHeaders;
        }
        try self.trailers.append(name, value);
        self.header_count += 1;

        self.line_buffer.clearRetainingCapacity();
        return line_end + 2;
    }
};

/// Detects CL/TE ambiguity which can lead to HTTP request smuggling.
/// Returns true if both Content-Length and Transfer-Encoding are present,
/// indicating a potential smuggling vector.
pub fn detectClTeAmbiguity(content_length: ?u64, transfer_encoding: ?[]const u8) bool {
    if (content_length != null and transfer_encoding != null) {
        return true;
    }
    return false;
}

test "detectClTeAmbiguity" {
    // Both present -> ambiguous
    try std.testing.expect(detectClTeAmbiguity(100, "chunked"));
    // Only CL -> not ambiguous
    try std.testing.expect(!detectClTeAmbiguity(100, null));
    // Only TE -> not ambiguous
    try std.testing.expect(!detectClTeAmbiguity(null, "chunked"));
    // Neither -> not ambiguous
    try std.testing.expect(!detectClTeAmbiguity(null, null));
}

test "Parser request line" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    const data = "GET /api/users HTTP/1.1\r\nHost: httpbun.com\r\n\r\n";
    _ = try parser.feed(data);

    try std.testing.expect(parser.isComplete());
    try std.testing.expectEqual(types.Method.GET, parser.method.?);
    try std.testing.expectEqualStrings("/api/users", parser.path.?);
}

test "Parser response" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    const data = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
    _ = try parser.feed(data);

    try std.testing.expect(parser.isComplete());
    try std.testing.expectEqual(@as(?u16, 200), parser.status_code);
    try std.testing.expectEqualStrings("Hello", parser.getBody());
}

test "Parser chunked encoding" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    const data = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n";
    _ = try parser.feed(data);

    try std.testing.expect(parser.isComplete());
    try std.testing.expectEqualStrings("Hello", parser.getBody());
}

test "Parser response body by close (finishEof)" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    const data = "HTTP/1.1 200 OK\r\n\r\nHello";
    _ = try parser.feed(data);
    try std.testing.expect(!parser.isComplete());
    parser.finishEof();
    try std.testing.expect(parser.isComplete());
    try std.testing.expectEqualStrings("Hello", parser.getBody());
}

test "Parser chunked with extension and split CRLF" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    _ = try parser.feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    _ = try parser.feed("5;foo=bar\r\nHel");
    _ = try parser.feed("lo\r");
    _ = try parser.feed("\n0\r\n\r\n");

    try std.testing.expect(parser.isComplete());
    try std.testing.expectEqualStrings("Hello", parser.getBody());
}

test "Parser headers" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    const data = "GET / HTTP/1.1\r\nHost: httpbun.com\r\nUser-Agent: test\r\n\r\n";
    _ = try parser.feed(data);

    try std.testing.expectEqualStrings("httpbun.com", parser.headers.get("Host").?);
    try std.testing.expectEqualStrings("test", parser.headers.get("User-Agent").?);
}

test "Parser preserves interleaved duplicate response headers" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    _ = try parser.feed(
        "HTTP/1.1 200 OK\r\n" ++
            "X-A: 1\r\n" ++
            "X-B: x\r\n" ++
            "X-A: 2\r\n" ++
            "Set-Cookie: a=1\r\n" ++
            "Set-Cookie: b=2\r\n" ++
            "Content-Length: 0\r\n\r\n",
    );

    const entries = parser.headers.iterator();
    try std.testing.expectEqualStrings("X-A", entries[0].name);
    try std.testing.expectEqualStrings("X-B", entries[1].name);
    try std.testing.expectEqualStrings("X-A", entries[2].name);
    const x_a = try parser.headers.getAll("X-A", allocator);
    defer allocator.free(x_a);
    try std.testing.expectEqual(@as(usize, 2), x_a.len);
    try std.testing.expectEqualStrings("1", x_a[0]);
    try std.testing.expectEqualStrings("2", x_a[1]);
    const cookies = try parser.headers.getAll("Set-Cookie", allocator);
    defer allocator.free(cookies);
    try std.testing.expectEqual(@as(usize, 2), cookies.len);
}

test "Parser reset" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    _ = try parser.feed("GET / HTTP/1.1\r\n\r\n");
    try std.testing.expect(parser.isComplete());

    parser.reset();
    try std.testing.expect(!parser.isComplete());
    try std.testing.expect(parser.method == null);
}

test "Parser Content-Length comma-separated list (identical values)" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    // RFC 7230 3.3.3 errata: comma-separated Content-Length values that are identical
    const data = "HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nHello";
    _ = try parser.feed(data);

    try std.testing.expect(parser.isComplete());
    try std.testing.expectEqual(@as(?u64, 5), parser.content_length);
    try std.testing.expectEqualStrings("Hello", parser.getBody());
}

test "Parser Content-Length comma-separated list (conflicting values)" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    // RFC 7230 3.3.3: conflicting Content-Length values must be rejected.
    const data = "HTTP/1.1 200 OK\r\nContent-Length: 5, 10\r\n\r\nHello";
    const result = parser.feed(data);

    try std.testing.expectError(error.InvalidContentLength, result);
}

test "Parser Transfer-Encoding on HTTP/1.0 is rejected" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    // RFC 7230 3.3.1: Transfer-Encoding is not allowed in HTTP/1.0.
    const data = "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n";
    const result = parser.feed(data);

    try std.testing.expectError(error.InvalidChunkEncoding, result);
}

test "Parser Transfer-Encoding non-chunked is rejected" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    // Non-chunked Transfer-Encoding (e.g., gzip) is not supported.
    const data = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n";
    const result = parser.feed(data);

    try std.testing.expectError(error.InvalidChunkEncoding, result);
}

test "Parser Transfer-Encoding not last coding is rejected" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    // chunked must be the last transfer coding
    const data = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n";
    const result = parser.feed(data);

    try std.testing.expectError(error.InvalidChunkEncoding, result);
}

test "Parser rejects gzip before chunked and long transfer encoding safely" {
    var parser = Parser.initResponse(std.testing.allocator);
    defer parser.deinit();
    try std.testing.expectError(
        error.InvalidChunkEncoding,
        parser.feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
    );

    parser.reset();
    parser.mode = .response;
    parser.state = .status_line;
    var value: [300]u8 = undefined;
    @memset(&value, 'a');
    var message: [400]u8 = undefined;
    const wire = try std.fmt.bufPrint(
        &message,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: {s}\r\n\r\n",
        .{&value},
    );
    try std.testing.expectError(error.InvalidChunkEncoding, parser.feed(wire));
}

test "Parser rejects Content-Length with Transfer-Encoding" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    const data = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\n\r\n5\r\nHello\r\n0\r\n\r\n";
    try std.testing.expectError(error.ConflictingFramingHeaders, parser.feed(data));
}

test "Parser Connection header tracking" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    const data = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    _ = try parser.feed(data);

    try std.testing.expect(parser.isComplete());
    try std.testing.expect(parser.connection_close);
    try std.testing.expect(!parser.isKeepAlive());
}

test "Parser HTTP/1.1 default keep-alive" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    const data = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    _ = try parser.feed(data);

    try std.testing.expect(parser.isComplete());
    try std.testing.expect(parser.isKeepAlive());
}

test "Parser HTTP/1.0 default close" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    const data = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    _ = try parser.feed(data);

    try std.testing.expect(parser.isComplete());
    try std.testing.expect(!parser.isKeepAlive());
}

test "Parser HTTP/1.0 with Connection: keep-alive" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    const data = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
    _ = try parser.feed(data);

    try std.testing.expect(parser.isComplete());
    try std.testing.expect(parser.connection_keep_alive);
    try std.testing.expect(parser.isKeepAlive());
}

test "Parser body size limit exceeded" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();
    parser.max_body_size = 5; // Only allow 5 bytes

    const data = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789";
    const result = parser.feed(data);

    try std.testing.expectError(error.BodyTooLarge, result);
}

test "Parser body size limit chunked" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();
    parser.max_body_size = 3; // Only allow 3 bytes

    const data = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n";
    const result = parser.feed(data);

    try std.testing.expectError(error.BodyTooLarge, result);
}

test "Parser body size limit 0 means unlimited" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();
    parser.max_body_size = 0; // Unlimited

    const data = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789";
    _ = try parser.feed(data);

    try std.testing.expect(parser.isComplete());
    try std.testing.expectEqualStrings("0123456789", parser.getBody());
}

test "Parser reset clears new fields" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    const data = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    _ = try parser.feed(data);

    try std.testing.expect(parser.connection_close);

    parser.reset();
    try std.testing.expect(!parser.connection_close);
    try std.testing.expect(!parser.connection_keep_alive);
    try std.testing.expect(!parser.transfer_encoding_seen);
}

test "Parser case-insensitive Content-Length" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    const data = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nHello";
    _ = try parser.feed(data);

    try std.testing.expect(parser.isComplete());
    try std.testing.expectEqual(@as(?u64, 5), parser.content_length);
    try std.testing.expectEqualStrings("Hello", parser.getBody());
}

test "Parser multiple Content-Length with spaces" {
    const allocator = std.testing.allocator;
    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    // With spaces around the comma
    const data = "HTTP/1.1 200 OK\r\nContent-Length: 5 , 5\r\n\r\nHello";
    _ = try parser.feed(data);

    try std.testing.expect(parser.isComplete());
    try std.testing.expectEqual(@as(?u64, 5), parser.content_length);
}

test "sink parser and request progress handle greater than four GiB with bounded memory" {
    const target: u64 = 5 * 1024 * 1024 * 1024 + 123;
    var body_chunk: [64 * 1024]u8 = undefined;
    @memset(&body_chunk, 0xa5);

    const Counter = struct {
        total: u64 = 0,
        checksum: u64 = 0,

        fn write(context: *anyopaque, data: []const u8) !usize {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.total += data.len;
            if (data.len > 0) self.checksum +%= @as(u64, data[0]) *% data.len;
            return data.len;
        }
    };

    var storage: [64 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var parser = Parser.initResponse(fixed.allocator());
    defer parser.deinit();
    var counter = Counter{};
    var sink = BodySink{ .context = &counter, .writeFn = Counter.write };
    var header_buffer: [128]u8 = undefined;
    const header = try std.fmt.bufPrint(
        &header_buffer,
        "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n",
        .{target},
    );
    _ = try parser.feedTo(header, &sink);
    var remaining = target;
    while (remaining > 0) {
        const amount: usize = @intCast(@min(remaining, body_chunk.len));
        const consumed = try parser.feedTo(body_chunk[0..amount], &sink);
        try std.testing.expectEqual(amount, consumed);
        remaining -= amount;
    }
    try std.testing.expect(parser.isComplete());
    try std.testing.expectEqual(target, counter.total);
    try std.testing.expectEqual(target, parser.body_bytes);

    const RequestProgress = @import("../client/operation.zig").RequestProgress;
    var known = RequestProgress{ .mode = .{ .content_length = target } };
    remaining = target;
    while (remaining > 0) {
        const amount: usize = @intCast(@min(remaining, body_chunk.len));
        const next = try known.validateWrite(amount);
        known.commit(next);
        remaining -= amount;
    }
    try known.finish();
    try std.testing.expectEqual(target, known.bytes);

    var chunk_storage: [64 * 1024]u8 = undefined;
    var chunk_fixed = std.heap.FixedBufferAllocator.init(&chunk_storage);
    var chunked = Parser.initResponse(chunk_fixed.allocator());
    defer chunked.deinit();
    var chunk_counter = Counter{};
    var chunk_sink = BodySink{ .context = &chunk_counter, .writeFn = Counter.write };
    _ = try chunked.feedTo(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        &chunk_sink,
    );
    remaining = target;
    while (remaining > 0) {
        const amount: usize = @intCast(@min(remaining, body_chunk.len));
        var size_buffer: [32]u8 = undefined;
        const size_line = try std.fmt.bufPrint(&size_buffer, "{x}\r\n", .{amount});
        _ = try chunked.feedTo(size_line, &chunk_sink);
        const consumed = try chunked.feedTo(body_chunk[0..amount], &chunk_sink);
        try std.testing.expectEqual(amount, consumed);
        _ = try chunked.feedTo("\r\n", &chunk_sink);
        remaining -= amount;
    }
    _ = try chunked.feedTo("0\r\n\r\n", &chunk_sink);
    try std.testing.expect(chunked.isComplete());
    try std.testing.expectEqual(target, chunk_counter.total);
}

test "parser headers trailers and buffering clean up on every allocation failure" {
    const Case = struct {
        fn run(allocator: Allocator) !void {
            var parser = Parser.initResponse(allocator);
            defer parser.deinit();
            _ = try parser.feed(
                "HTTP/1.1 200 OK\r\n" ++
                    "Transfer-Encoding: chunked\r\n" ++
                    "X-Dupe: one\r\n" ++
                    "X-Dupe: two\r\n\r\n" ++
                    "5\r\nhello\r\n" ++
                    "0\r\nX-Trailer: done\r\n\r\n",
            );
            try std.testing.expect(parser.isComplete());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Case.run, .{});
}
