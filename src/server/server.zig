//! HTTP Server Implementation for httpx.zig
//!
//! Production-ready HTTP server with comprehensive features:
//!
//! - Pattern-based routing with path parameters
//! - Middleware stack support
//! - Context-based request handling
//! - JSON response helpers
//! - Static file serving
//! - Cross-platform (Linux, Windows, macOS)

const std = @import("std");
const builtin = @import("builtin");
const tint = @import("tint");
const mem = std.mem;
const Allocator = mem.Allocator;
const net = @import("../net/compat.zig");

const types = @import("../core/types.zig");
const Request = @import("../core/request.zig").Request;
const Response = @import("../core/response.zig").Response;
const ResponseBuilder = @import("../core/response.zig").ResponseBuilder;
const Headers = @import("../core/headers.zig").Headers;
const HeaderName = @import("../core/headers.zig").HeaderName;
const Parser = @import("../protocol/parser.zig").Parser;
const status_mod = @import("../core/status.zig");
const http = @import("../protocol/http.zig");
const hpack = @import("../protocol/hpack.zig");
const h2stream = @import("../protocol/stream.zig");
const qpack = @import("../protocol/qpack.zig");
const quic = @import("../protocol/quic.zig");
const Socket = @import("../net/socket.zig").Socket;
const TcpListener = @import("../net/socket.zig").TcpListener;
const UdpSocket = @import("../net/socket.zig").UdpSocket;
const tls_mod = @import("../tls/tls.zig");
const alpn = @import("../tls/alpn.zig");
const Router = @import("router.zig").Router;
const router_mod = @import("router.zig");
const Middleware = @import("middleware.zig").Middleware;
const common = @import("../data/common.zig");
const list_writer = @import("../io/list_writer.zig");
const io_util = @import("../io/any_io.zig");
const IoContext = @import("../io/context.zig").IoContext;
const Deadline = @import("../io/context.zig").Deadline;
const Executor = @import("../concurrency/executor.zig").Executor;

const Metrics = @import("../io/metrics.zig").Metrics;

const defaultIo = io_util.defaultIo;
const sleepMs = io_util.sleepMsI;

pub const CookieOptions = common.CookieOptions;
pub const SameSite = common.SameSite;

/// Strategy for handling bind conflicts on startup.
pub const PortConflictStrategy = enum {
    /// Fail immediately when the configured port is unavailable.
    fail,
    /// Retry on subsequent ports (`port + 1`, `port + 2`, ...) until a free port is found.
    increment,
};

pub const SSEEvent = @import("../protocol/sse.zig").Event;

/// Pre-route hook called after parsing the request and before route matching.
pub const PreRouteHook = *const fn (*Context) anyerror!void;

pub const LogLevel = enum {
    debug,
    info,
    warn,
    err,
};

pub const LogFn = *const fn (level: LogLevel, message: []const u8) void;

/// Error callback type. Called when a handler error occurs.
pub const ErrorCallback = *const fn (err: anyerror, ctx: *Context) void;

/// Lifecycle hook types for server events.
pub const LifecycleHook = *const fn (*Server) void;

/// Server configuration.
pub const ServerConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 8080,
    port_conflict: PortConflictStrategy = .fail,
    max_port_tries: u16 = 32,
    max_body_size: usize = 10 * 1024 * 1024,
    max_header_size: usize = 8192,
    max_headers: usize = 100,
    request_timeout_ms: u64 = 30_000,
    keep_alive_timeout_ms: u64 = 60_000,
    write_timeout_ms: u64 = 30_000,
    shutdown_timeout_ms: u64 = 10_000,
    max_connections: u32 = 1000,
    keep_alive: bool = true,
    threads: u32 = 0,
    http2_enabled: bool = false,
    http3_enabled: bool = false,
    /// Deprecated. HTTP/2 server push is disabled until its stream and HPACK
    /// state can be synchronized with concurrent request processing.
    enable_push: bool = false,
    http2_settings: types.HTTP2Settings = .{},
    http3_settings: types.HTTP3Settings = .{},
    log_fn: ?LogFn = null,
    log_level: LogLevel = .info,
    unix_path: ?[]const u8 = null,
    tls_enabled: bool = false,
    tls_cert_path: ?[]const u8 = null,
    tls_key_path: ?[]const u8 = null,
    tls_alpn_protocols: []const []const u8 = &.{ "h2", "http/1.1" },
    on_starting: ?LifecycleHook = null,
    on_started: ?LifecycleHook = null,
    on_stopping: ?LifecycleHook = null,
    on_stopped: ?LifecycleHook = null,
    on_error: ?ErrorCallback = null,
    metrics: ?*Metrics = null,
};

/// File-serving options used by `Context.fileWithOptions`.
pub const FileResponseOptions = struct {
    content_type: ?[]const u8 = null,
    cache_control: ?[]const u8 = null,
    add_etag: bool = true,
    add_nosniff: bool = true,
    conditional_get: bool = true,
};

/// A type-erased writer that wraps either a plain socket or a TLS connection.
/// Used by Context streaming methods to write directly to the connection.
pub const StreamWriter = struct {
    context: ?*anyopaque,
    writeFn: *const fn (?*anyopaque, []const u8) anyerror!usize,
    writeAllFn: *const fn (?*anyopaque, []const u8) anyerror!void,
    allocator: Allocator,

    /// Creates a StreamWriter wrapping a plain socket.
    pub fn fromSocket(allocator: Allocator, sock: *Socket) StreamWriter {
        const S = struct {
            fn write(ctx: ?*anyopaque, data: []const u8) anyerror!usize {
                const s: *Socket = @ptrCast(@alignCast(ctx orelse return error.NoContext));
                return s.send(data);
            }
            fn writeAll_(ctx: ?*anyopaque, data: []const u8) anyerror!void {
                const s: *Socket = @ptrCast(@alignCast(ctx orelse return error.NoContext));
                return s.sendAll(data);
            }
        };
        return .{
            .context = sock,
            .writeFn = S.write,
            .writeAllFn = S.writeAll_,
            .allocator = allocator,
        };
    }

    /// Creates a StreamWriter wrapping a TLS connection.
    pub fn fromTLS(allocator: Allocator, conn: *tls_mod.Connection) StreamWriter {
        const S = struct {
            fn write(ctx: ?*anyopaque, data: []const u8) anyerror!usize {
                const c: *tls_mod.Connection = @ptrCast(@alignCast(ctx orelse return error.NoContext));
                return c.write(data);
            }
            fn writeAll_(ctx: ?*anyopaque, data: []const u8) anyerror!void {
                const c: *tls_mod.Connection = @ptrCast(@alignCast(ctx orelse return error.NoContext));
                return c.writeAll(data);
            }
        };
        return .{
            .context = conn,
            .writeFn = S.write,
            .writeAllFn = S.writeAll_,
            .allocator = allocator,
        };
    }

    pub fn write(self: StreamWriter, data: []const u8) !usize {
        return self.writeFn(self.context, data);
    }

    pub fn writeAll(self: StreamWriter, data: []const u8) !void {
        try self.writeAllFn(self.context, data);
    }

    /// Writes raw bytes directly (no chunked encoding).
    /// Use this with startRawStreaming or startSSEStreaming.
    pub fn writeRaw(self: StreamWriter, data: []const u8) !void {
        try self.writeAllFn(self.context, data);
    }
};

/// Request context passed to handlers.
pub const Context = struct {
    allocator: Allocator,
    request: *Request,
    response: ResponseBuilder,
    params: std.StringHashMap([]const u8),
    data: std.StringHashMap(*anyopaque),
    server: ?*Server = null,
    remote_ip: ?[]const u8 = null,
    streaming_done: bool = false,

    const Self = @This();

    /// Creates a new context for a request.
    pub fn init(allocator: Allocator, req: *Request) Self {
        return .{
            .allocator = allocator,
            .request = req,
            .response = ResponseBuilder.init(allocator),
            .params = std.StringHashMap([]const u8).init(allocator),
            .data = std.StringHashMap(*anyopaque).init(allocator),
        };
    }

    /// Releases context resources.
    pub fn deinit(self: *Self) void {
        self.response.deinit();
        self.params.deinit();
        self.data.deinit();
    }

    /// Returns a URL parameter by name.
    pub fn param(self: *const Self, name: []const u8) ?[]const u8 {
        return self.params.get(name);
    }

    /// Returns a query parameter by name.
    pub fn query(self: *const Self, name: []const u8) ?[]const u8 {
        const query_str = self.request.uri.query orelse return null;
        return common.queryValue(query_str, name);
    }

    /// Returns a request header by name.
    pub fn header(self: *const Self, name: []const u8) ?[]const u8 {
        return self.request.headers.get(name);
    }

    /// Returns the raw Authorization header value.
    pub fn authorization(self: *const Self) ?[]const u8 {
        return self.request.headers.get(HeaderName.AUTHORIZATION);
    }

    /// Returns Bearer token bytes when Authorization is `Bearer <token>`.
    pub fn bearerToken(self: *const Self) ?[]const u8 {
        const raw = self.authorization() orelse return null;
        if (raw.len < 7) return null;
        if (!std.ascii.eqlIgnoreCase(raw[0..7], "Bearer ")) return null;
        return mem.trim(u8, raw[7..], " \t");
    }

    /// Returns true when request Content-Type matches the expected media type.
    pub fn hasContentType(self: *const Self, expected: []const u8) bool {
        return self.request.hasContentType(expected);
    }

    /// Returns true when request Content-Type is application/json.
    pub fn isJson(self: *const Self) bool {
        return self.request.isJsonContent();
    }

    /// Returns true when request Content-Type is application/x-www-form-urlencoded.
    pub fn isFormUrlEncoded(self: *const Self) bool {
        return self.request.isFormContent();
    }

    /// Returns true when request Accept allows the given media type.
    pub fn accepts(self: *const Self, media_type: []const u8) bool {
        return self.request.accepts(media_type);
    }

    /// Returns true when request Accept allows application/json.
    pub fn acceptsJson(self: *const Self) bool {
        return self.request.acceptsJson();
    }

    /// Returns a parsed cookie value by name from the request Cookie header.
    pub fn cookie(self: *const Self, name: []const u8) ?[]const u8 {
        const cookie_header = self.request.headers.get(HeaderName.COOKIE) orelse return null;
        return common.cookieValue(cookie_header, name);
    }

    /// Returns the connection IP address, if available.
    /// Used by rate limiting middleware to identify the client.
    pub fn connectionIp(self: *const Self) []const u8 {
        return self.remote_ip orelse "0.0.0.0";
    }

    /// Sets the response status code.
    pub fn status(self: *Self, code: u16) *Self {
        _ = self.response.status(code);
        return self;
    }

    /// Sets a response header.
    pub fn setHeader(self: *Self, name: []const u8, value: []const u8) !void {
        _ = try self.response.header(name, value);
    }

    /// Appends a Set-Cookie header with common cookie attributes.
    pub fn setCookie(self: *Self, name: []const u8, value: []const u8, options: CookieOptions) !void {
        const set_cookie = try common.buildSetCookieHeader(self.allocator, name, value, options);
        defer self.allocator.free(set_cookie);
        try self.response.headers.append(HeaderName.SET_COOKIE, set_cookie);
    }

    /// Appends a Set-Cookie header that removes a cookie via Max-Age=0.
    pub fn removeCookie(self: *Self, name: []const u8, options: CookieOptions) !void {
        var remove_options = options;
        remove_options.max_age = 0;
        const remove_value = try common.buildSetCookieHeader(self.allocator, name, "", remove_options);
        defer self.allocator.free(remove_value);
        try self.response.headers.append(HeaderName.SET_COOKIE, remove_value);
    }

    /// Sends a plain text response.
    pub fn text(self: *Self, data: []const u8) !Response {
        _ = try self.response.header(HeaderName.CONTENT_TYPE, "text/plain; charset=utf-8");
        _ = self.response.body(data);
        return self.response.build();
    }

    /// Sends an HTML response.
    pub fn html(self: *Self, data: []const u8) !Response {
        _ = try self.response.header(HeaderName.CONTENT_TYPE, "text/html; charset=utf-8");
        _ = self.response.body(data);
        return self.response.build();
    }

    /// Sends a file response.
    pub fn file(self: *Self, path: []const u8) !Response {
        return self.fileWithOptions(path, .{});
    }

    /// Sends a file response with an explicit content type override.
    pub fn fileAs(self: *Self, path: []const u8, content_type: []const u8) !Response {
        return self.fileWithOptions(path, .{ .content_type = content_type });
    }

    /// Sends a file as an attachment download.
    pub fn download(self: *Self, path: []const u8, filename: ?[]const u8) !Response {
        var response = try self.file(path);

        if (filename) |name| {
            for (name) |c| {
                if (c == '"' or c == '\\' or c == '\r' or c == '\n' or c == 0) {
                    return error.InvalidFilename;
                }
            }
            const disposition = try std.fmt.allocPrint(self.allocator, "attachment; filename=\"{s}\"", .{name});
            defer self.allocator.free(disposition);
            try response.headers.set(HeaderName.CONTENT_DISPOSITION, disposition);
        } else {
            try response.headers.set(HeaderName.CONTENT_DISPOSITION, "attachment");
        }

        return response;
    }

    /// Sends a file response with production-oriented static-file options.
    /// Supports Range requests (RFC 7233) for partial content (206) and range validation (416).
    pub fn fileWithOptions(self: *Self, path: []const u8, options: FileResponseOptions) !Response {
        // Security: Reject paths containing null bytes (can truncate in C APIs)
        for (path) |c| {
            if (c == 0) return self.status(status_mod.StatusCode.BAD_REQUEST).text("Bad Request: Null byte in path");
        }
        // Security: Reject paths with path traversal sequences
        if (mem.indexOf(u8, path, "..") != null) {
            return self.status(status_mod.StatusCode.FORBIDDEN).text("Forbidden: Path Traversal Detected");
        }
        // Security: Reject absolute paths (Unix) or drive letters (Windows)
        if (path.len > 0 and path[0] == '/') {
            return self.status(status_mod.StatusCode.FORBIDDEN).text("Forbidden: Absolute path");
        }
        if (path.len >= 2 and path[1] == ':') {
            return self.status(status_mod.StatusCode.FORBIDDEN).text("Forbidden: Absolute path");
        }
        // Security: Reject UNC paths on Windows (\\server\share\...)
        if (path.len >= 2 and path[0] == '\\' and path[1] == '\\') {
            return self.status(status_mod.StatusCode.FORBIDDEN).text("Forbidden: UNC path");
        }
        const io = defaultIo();
        var f = std.Io.Dir.cwd().openFile(io, path, .{}) catch return self.status(status_mod.StatusCode.NOT_FOUND).text("Not Found");
        defer f.close(io);

        const stat = try f.stat(io);
        const content_type = options.content_type orelse common.mimeTypeFromPath(path);

        _ = try self.response.header(HeaderName.CONTENT_TYPE, content_type);
        _ = try self.response.header(HeaderName.ACCEPT_RANGES, "bytes");

        if (options.cache_control) |cache_control| {
            _ = try self.response.header(HeaderName.CACHE_CONTROL, cache_control);
        }

        if (options.add_nosniff) {
            _ = try self.response.header(HeaderName.X_CONTENT_TYPE_OPTIONS, "nosniff");
        }

        var etag_value: ?[]u8 = null;
        defer if (etag_value) |etag| self.allocator.free(etag);

        if (options.add_etag) {
            etag_value = try buildStaticEtag(self.allocator, path, stat);
            _ = try self.response.header(HeaderName.ETAG, etag_value.?);

            if (options.conditional_get) {
                if (self.request.headers.get(HeaderName.IF_NONE_MATCH)) |if_none_match| {
                    if (ifNoneMatchMatches(if_none_match, etag_value.?)) {
                        _ = self.response.status(status_mod.StatusCode.NOT_MODIFIED);
                        return self.response.build();
                    }
                }
            }
        }

        if (self.request.method == .HEAD) {
            var len_buf: [32]u8 = undefined;
            const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{stat.size}) catch unreachable;
            _ = try self.response.header(HeaderName.CONTENT_LENGTH, len_str);
            return self.response.build();
        }

        if (stat.size > @as(u64, std.math.maxInt(usize))) {
            return error.ResponseTooLarge;
        }

        const file_size: usize = @intCast(stat.size);

        // Parse Range header for partial content support.
        if (self.request.headers.get("Range")) |range_header| {
            return self.serveRangeRequest(f, io, range_header, file_size);
        }

        // Full content response.
        var len_buf: [32]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{file_size}) catch unreachable;
        _ = try self.response.header(HeaderName.CONTENT_LENGTH, len_str);

        const content = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(content);

        const read_n = try f.readPositionalAll(io, content, 0);
        if (read_n != file_size) {
            return error.UnexpectedEof;
        }

        _ = self.response.body(content);
        return self.response.build();
    }

    /// Handles Range request for partial content (206) and range validation (416).
    fn serveRangeRequest(
        self: *Self,
        f: std.Io.File,
        io: anytype,
        range_header: []const u8,
        file_size: usize,
    ) !Response {
        // Parse "bytes=START-END" or "bytes=START-" or "bytes=-SUFFIX"
        const range_value = mem.trim(u8, range_header, " \t\r\n");
        if (!mem.startsWith(u8, range_value, "bytes=")) {
            return self.status(status_mod.StatusCode.RANGE_NOT_SATISFIABLE).text("Invalid Range");
        }
        const range_spec = range_value[6..];

        var start: usize = 0;
        var end: usize = file_size -| 1;
        var is_suffix = false;

        if (mem.startsWith(u8, range_spec, "-")) {
            // Suffix range: bytes=-500 (last 500 bytes)
            is_suffix = true;
            const suffix_len = std.fmt.parseInt(usize, range_spec[1..], 10) catch {
                return self.status(status_mod.StatusCode.RANGE_NOT_SATISFIABLE).text("Invalid Range");
            };
            if (suffix_len == 0) {
                return self.status(status_mod.StatusCode.RANGE_NOT_SATISFIABLE).text("Invalid Range");
            }
            start = if (file_size > suffix_len) file_size - suffix_len else 0;
            end = file_size -| 1;
        } else if (mem.endsWith(u8, range_spec, "-")) {
            // Open-ended range: bytes=100-
            const start_str = range_spec[0 .. range_spec.len - 1];
            start = std.fmt.parseInt(usize, start_str, 10) catch {
                return self.status(status_mod.StatusCode.RANGE_NOT_SATISFIABLE).text("Invalid Range");
            };
            end = file_size -| 1;
        } else {
            // Explicit range: bytes=100-200
            var parts = mem.splitScalar(u8, range_spec, '-');
            const start_str = parts.next() orelse {
                return self.status(status_mod.StatusCode.RANGE_NOT_SATISFIABLE).text("Invalid Range");
            };
            const end_str = parts.next() orelse {
                return self.status(status_mod.StatusCode.RANGE_NOT_SATISFIABLE).text("Invalid Range");
            };
            start = std.fmt.parseInt(usize, start_str, 10) catch {
                return self.status(status_mod.StatusCode.RANGE_NOT_SATISFIABLE).text("Invalid Range");
            };
            end = std.fmt.parseInt(usize, end_str, 10) catch {
                return self.status(status_mod.StatusCode.RANGE_NOT_SATISFIABLE).text("Invalid Range");
            };
        }

        // Validate range.
        if (start >= file_size or end >= file_size or start > end) {
            return self.status(status_mod.StatusCode.RANGE_NOT_SATISFIABLE).text("Range Not Satisfiable");
        }

        const content_length = end - start + 1;

        // Set 206 Partial Content headers.
        _ = self.response.status(status_mod.StatusCode.PARTIAL_CONTENT);

        var cl_buf: [64]u8 = undefined;
        const content_range = std.fmt.bufPrint(&cl_buf, "bytes {d}-{d}/{d}", .{ start, end, file_size }) catch unreachable;
        _ = try self.response.header("Content-Range", content_range);

        var len_buf: [32]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{content_length}) catch unreachable;
        _ = try self.response.header(HeaderName.CONTENT_LENGTH, len_str);

        // Read the requested range.
        const content = try self.allocator.alloc(u8, content_length);
        defer self.allocator.free(content);

        const read_n = try f.readPositionalAll(io, content, start);
        if (read_n != content_length) {
            return error.UnexpectedEof;
        }

        _ = self.response.body(content);
        return self.response.build();
    }

    /// Sends chunked transfer-encoded payload with optional trailers.
    pub fn chunked(self: *Self, data: []const u8, trailers: ?*const Headers) !Response {
        const encoded = try http.encodeChunkedBody(data, trailers, self.allocator);
        defer self.allocator.free(encoded);

        _ = try self.response.header(HeaderName.TRANSFER_ENCODING, "chunked");
        if (trailers) |trailer_headers| {
            const trailer_names = try trailerHeaderNames(self.allocator, trailer_headers);
            defer self.allocator.free(trailer_names);
            _ = try self.response.header("Trailer", trailer_names);
        }
        _ = self.response.body(encoded);
        return self.response.build();
    }

    /// Sends one-shot Server-Sent Events payload.
    pub fn sse(self: *Self, events: []const SSEEvent) !Response {
        var payload = std.ArrayList(u8).empty;
        defer payload.deinit(self.allocator);
        const writer = list_writer.init(self.allocator, &payload);

        for (events) |evt| {
            if (evt.id) |id| try writer.print("id: {s}\n", .{id});
            if (evt.event) |name| try writer.print("event: {s}\n", .{name});
            if (evt.retry_ms) |retry_ms| try writer.print("retry: {d}\n", .{retry_ms});

            var lines = mem.splitScalar(u8, evt.data, '\n');
            while (lines.next()) |line| {
                try writer.print("data: {s}\n", .{line});
            }
            try writer.writeAll("\n");
        }

        _ = try self.response.header(HeaderName.CONTENT_TYPE, "text/event-stream; charset=utf-8");
        _ = try self.response.header(HeaderName.CACHE_CONTROL, "no-cache");
        _ = try self.response.header(HeaderName.CONNECTION, "keep-alive");
        _ = self.response.body(payload.items);
        return self.response.build();
    }

    /// Sends a JSON response.
    pub fn json(self: *Self, value: anytype) !Response {
        _ = try self.response.json(value);
        return self.response.build();
    }

    /// Parses the request body as JSON into the given type.
    /// The caller must call `deinit()` on the returned `std.json.Parsed(T)`.
    pub fn jsonBody(self: *const Self, comptime T: type, options: std.json.ParseOptions) !std.json.Parsed(T) {
        const body = self.request.body orelse return error.NoBody;
        return std.json.parseFromSlice(T, self.allocator, body, options);
    }

    /// Parses the request body as JSON into the given type using leaky allocation.
    pub fn jsonBodyLeaky(self: *const Self, comptime T: type, options: std.json.ParseOptions) !T {
        const body = self.request.body orelse return error.NoBody;
        return std.json.parseFromSliceLeaky(T, self.allocator, body, options);
    }

    /// Parses the request body as a dynamic JSON value.
    /// The caller must call `deinit()` on the returned `ParsedJson`.
    pub fn jsonValue(self: *const Self) !@import("../data/json.zig").ParsedJson {
        const body = self.request.body orelse return error.NoBody;
        return @import("../data/json.zig").Json.parseValue(self.allocator, body);
    }

    /// Returns 415 Unsupported Media Type if the request Content-Type is not JSON.
    /// Use this to guard handlers that require JSON input.
    pub fn requireJson(self: *const Self) !void {
        if (!self.isJson()) {
            return error.JsonContentTypeRequired;
        }
    }

    /// Returns the X-Request-ID header value, or null if not set.
    pub fn requestId(self: *const Self) ?[]const u8 {
        return self.request.headers.get("X-Request-ID");
    }

    /// Parses the request body as URL-encoded form data into a StringHashMap.
    /// Caller owns the returned map and its keys/values.
    pub fn formBody(self: *const Self) !std.StringHashMap([]const u8) {
        const body = self.request.body orelse return error.NoBody;
        if (!self.isFormUrlEncoded()) return error.InvalidContentType;
        return common.parseFormBody(self.allocator, body);
    }

    /// Sends a redirect response.
    pub fn redirect(self: *Self, url: []const u8, code: u16) !Response {
        _ = self.response.status(code);
        _ = try self.response.header(HeaderName.LOCATION, url);
        return self.response.build();
    }

    /// Sends a 204 No Content response.
    pub fn noContent(self: *Self) !Response {
        _ = self.response.status(status_mod.StatusCode.NO_CONTENT);
        return self.response.build();
    }

    /// Starts a streaming response using chunked transfer encoding.
    /// Writes the response status line and headers directly to the socket,
    /// then returns a StreamWriter for writing body chunks.
    /// After calling finishStreaming(), the server will skip normal response formatting.
    pub fn startStreaming(self: *Self, status_code: u16, headers: ?*const Headers) !StreamWriter {
        const writer = self.getStreamWriter() orelse return error.NoStreamWriter;

        // Write status line
        try writer.writeAll("HTTP/1.1 ");
        const status_str = std.fmt.allocPrint(self.allocator, "{d}", .{status_code}) catch unreachable;
        defer self.allocator.free(status_str);
        try writer.writeAll(status_str);
        try writer.writeAll("\r\n");

        // Write headers
        if (headers) |h| {
            for (h.iterator()) |entry| {
                try writer.writeAll(entry.name);
                try writer.writeAll(": ");
                try writer.writeAll(entry.value);
                try writer.writeAll("\r\n");
            }
        }

        // Add Transfer-Encoding: chunked
        try writer.writeAll("Transfer-Encoding: chunked\r\n");
        try writer.writeAll("\r\n");

        self.streaming_done = true;
        return writer.*;
    }

    /// Writes a chunk to the streaming response body.
    pub fn writeChunk(self: *Self, data: []const u8) !void {
        const writer = self.getStreamWriter() orelse return error.NoStreamWriter;
        try http.writeChunkToWriter(writer, data);
    }

    /// Finishes the streaming response by writing the final empty chunk.
    pub fn finishStreaming(self: *Self) !void {
        const writer = self.getStreamWriter() orelse return error.NoStreamWriter;
        // Write the final empty chunk to signal end of body
        try writer.writeAll("0\r\n\r\n");
    }

    /// Starts a raw streaming response without Transfer-Encoding.
    /// Use this for protocols like SSE that have their own framing.
    pub fn startRawStreaming(self: *Self, status_code: u16, headers: ?*const Headers) !StreamWriter {
        const writer = self.getStreamWriter() orelse return error.NoStreamWriter;

        // Write status line
        try writer.writeAll("HTTP/1.1 ");
        const status_str = std.fmt.allocPrint(self.allocator, "{d}", .{status_code}) catch unreachable;
        defer self.allocator.free(status_str);
        try writer.writeAll(status_str);
        try writer.writeAll("\r\n");

        // Write headers
        if (headers) |h| {
            for (h.iterator()) |entry| {
                try writer.writeAll(entry.name);
                try writer.writeAll(": ");
                try writer.writeAll(entry.value);
                try writer.writeAll("\r\n");
            }
        }

        try writer.writeAll("\r\n");
        self.streaming_done = true;
        return writer.*;
    }

    /// Starts a streaming SSE response by writing headers and returning a writer.
    /// Use the returned writer to send SSE events incrementally.
    pub fn startSSEStreaming(self: *Self) !StreamWriter {
        var sse_headers = Headers.init(self.allocator);
        defer sse_headers.deinit();
        try sse_headers.append(HeaderName.CONTENT_TYPE, "text/event-stream; charset=utf-8");
        try sse_headers.append(HeaderName.CACHE_CONTROL, "no-cache");
        try sse_headers.append(HeaderName.CONNECTION, "keep-alive");
        return self.startRawStreaming(200, &sse_headers);
    }

    /// Streams Server-Sent Events incrementally.
    /// Writes each event as it's sent, rather than buffering the entire SSE payload.
    /// Must be called after startSSEStreaming.
    pub fn streamSSE(self: *Self, events: []const SSEEvent) !void {
        const writer = self.getStreamWriter() orelse return error.NoStreamWriter;
        for (events) |evt| {
            if (evt.id) |id| {
                _ = try writer.writeRaw("id: ");
                _ = try writer.writeRaw(id);
                _ = try writer.writeRaw("\n");
            }
            if (evt.event) |name| {
                _ = try writer.writeRaw("event: ");
                _ = try writer.writeRaw(name);
                _ = try writer.writeRaw("\n");
            }
            if (evt.retry_ms) |retry_ms| {
                const retry_str = std.fmt.allocPrint(self.allocator, "{d}", .{retry_ms}) catch unreachable;
                defer self.allocator.free(retry_str);
                _ = try writer.writeRaw("retry: ");
                _ = try writer.writeRaw(retry_str);
                _ = try writer.writeRaw("\n");
            }
            var lines = mem.splitScalar(u8, evt.data, '\n');
            while (lines.next()) |line| {
                _ = try writer.writeRaw("data: ");
                _ = try writer.writeRaw(line);
                _ = try writer.writeRaw("\n");
            }
            _ = try writer.writeRaw("\n");
        }
    }

    /// Gets the streaming writer from the context's data map.
    fn getStreamWriter(self: *Self) ?*StreamWriter {
        const raw = self.data.get("__stream_writer") orelse return null;
        return @ptrCast(@alignCast(raw));
    }
};

/// Handler function type.
pub const Handler = *const fn (*Context) anyerror!Response;

/// HTTP Server.
pub const Server = struct {
    allocator: Allocator,
    config: ServerConfig,
    router: Router,
    middleware: std.ArrayList(Middleware) = .empty,
    pre_route_hooks: std.ArrayList(PreRouteHook) = .empty,
    global_handler: ?Handler = null,
    listener: ?TcpListener = null,
    udp_socket: ?UdpSocket = null,
    unix_listener: ?@import("../net/unix.zig").UnixListener = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    active_connections: std.ArrayList(Socket) = .empty,
    active_conn_mutex: std.Io.Mutex = .init,
    active_conn_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    executor: ?Executor = null,
    executor_connections: std.ArrayList(Socket) = .empty,
    executor_conn_mutex: std.Io.Mutex = .init,
    server_tls_config: ?tls_mod.ServerTLSConfig = null,
    tls_init_mutex: std.Io.Mutex = .init,
    udp_thread: ?std.Thread = null,
    last_activity_ms: i64 = 0,

    const Self = @This();

    /// Creates a server with default configuration.
    pub fn init(allocator: Allocator) Self {
        return initWithConfig(allocator, .{});
    }

    /// Creates a server with custom configuration.
    pub fn initWithConfig(allocator: Allocator, config: ServerConfig) Self {
        var cfg = config;
        if (cfg.max_connections == 0) cfg.max_connections = 1000;
        if (cfg.max_port_tries == 0) cfg.max_port_tries = 1;
        if (cfg.request_timeout_ms == 0) cfg.request_timeout_ms = 30_000;
        if (cfg.keep_alive_timeout_ms == 0) cfg.keep_alive_timeout_ms = 60_000;

        var executor: ?Executor = null;
        if (cfg.threads > 0) {
            executor = Executor.initWithConfig(allocator, .{ .num_threads = cfg.threads });
        }

        return .{
            .allocator = allocator,
            .config = cfg,
            .router = Router.init(allocator),
            .executor = executor,
        };
    }

    /// Releases all server resources.
    pub fn deinit(self: *Self) void {
        self.router.deinit();
        self.middleware.deinit(self.allocator);
        self.pre_route_hooks.deinit(self.allocator);
        self.active_connections.deinit(self.allocator);
        self.executor_connections.deinit(self.allocator);
        if (self.listener) |*l| l.deinit();
        if (self.udp_socket) |*u| u.close();
        if (self.executor) |*e| {
            e.deinit();
        }
        if (self.server_tls_config) |*tc| tc.deinit();
    }

    /// Adds middleware to the server.
    pub fn use(self: *Self, mw: Middleware) !void {
        try self.middleware.append(self.allocator, mw);
    }

    /// Adds a pre-route hook executed before route matching.
    pub fn preRoute(self: *Self, hook: PreRouteHook) !void {
        try self.pre_route_hooks.append(self.allocator, hook);
    }

    /// Registers a global fallback handler for unmatched routes.
    pub fn global(self: *Self, handler: Handler) void {
        self.global_handler = handler;
    }

    /// Registers a route handler.
    pub fn route(self: *Self, method: types.Method, path: []const u8, handler: Handler) !void {
        try self.router.add(method, path, handler);
    }

    /// Registers a GET route.
    pub fn get(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.GET, path, handler);
    }

    /// Registers a POST route.
    pub fn post(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.POST, path, handler);
    }

    /// Registers a PUT route.
    pub fn put(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.PUT, path, handler);
    }

    /// Registers a DELETE route.
    pub fn delete(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.DELETE, path, handler);
    }

    /// Registers a PATCH route.
    pub fn patch(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.PATCH, path, handler);
    }

    /// Registers a HEAD route.
    pub fn head(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.HEAD, path, handler);
    }

    /// Registers an OPTIONS route.
    pub fn options(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.OPTIONS, path, handler);
    }

    /// Registers a TRACE route.
    pub fn trace(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.TRACE, path, handler);
    }

    /// Registers a CONNECT route.
    pub fn connect(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.CONNECT, path, handler);
    }

    /// Registers a handler for all standard HTTP methods on a path.
    pub fn any(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.GET, path, handler);
        try self.route(.POST, path, handler);
        try self.route(.PUT, path, handler);
        try self.route(.DELETE, path, handler);
        try self.route(.PATCH, path, handler);
        try self.route(.HEAD, path, handler);
        try self.route(.OPTIONS, path, handler);
        try self.route(.TRACE, path, handler);
        try self.route(.CONNECT, path, handler);
    }

    /// Starts the server and begins accepting connections.
    ///
    /// HTTP/3 is rejected until authenticated QUIC transport exists.
    pub fn listen(self: *Self) !void {
        if (self.config.http3_enabled) return error.UnsupportedHttpVersion;
        if (self.config.on_starting) |hook| hook(self);
        if (self.config.http3_enabled) return error.UnsupportedHttpVersion;

        if (self.config.unix_path) |path| {
            return self.listenUnix(path);
        }

        return self.listenTcp();
    }

    /// Spawns a background thread to run the server's listening loop.
    /// The caller is responsible for joining the returned Thread.
    pub fn listenInBackground(self: *Self) !std.Thread {
        if (self.config.http3_enabled) return error.UnsupportedHttpVersion;
        if (self.config.unix_path) |path| {
            if (self.unix_listener == null) {
                const unix_mod = @import("../net/unix.zig");
                self.unix_listener = try unix_mod.UnixListener.init(path);
            }
            return std.Thread.spawn(.{}, struct {
                fn run(s: *Self) void {
                    s.listen() catch |err| {
                        if (s.running.load(.acquire)) {
                            s.log(.err, "server error: {s}\n", .{@errorName(err)});
                        }
                    };
                }
            }.run, .{self});
        }

        // Standard HTTP/1.1 + HTTP/2 path.
        if (self.listener == null) {
            const backlog_u32: u32 = @max(self.config.max_connections, 1);
            const backlog: u31 = @intCast(@min(backlog_u32, @as(u32, std.math.maxInt(u31))));
            try self.bindTcpListener(backlog);
        }
        return std.Thread.spawn(.{}, struct {
            fn run(s: *Self) void {
                s.listen() catch |err| {
                    if (s.running.load(.acquire)) {
                        s.log(.err, "server error: {s}\n", .{@errorName(err)});
                    }
                };
            }
        }.run, .{self});
    }

    /// Logs a formatted message. If config.log_fn is provided, delegates to it.
    /// Otherwise, prints to stderr with tint.zig coloring based on log level.
    /// Messages below config.log_level are silently dropped.
    pub fn log(self: *const Self, level: LogLevel, comptime format: []const u8, args: anytype) void {
        if (@intFromEnum(level) < @intFromEnum(self.config.log_level)) return;
        if (self.config.log_fn) |log_fn| {
            var buf: [1024]u8 = undefined;
            if (std.fmt.bufPrint(&buf, format, args)) |msg| {
                log_fn(level, msg);
            } else |_| {
                log_fn(level, "[Log format failed or message too long]");
            }
        } else {
            const level_style = switch (level) {
                .debug => tint.style(.{ .fg = .{ .ansi4 = .bright_black }, .dim = true }),
                .info => tint.style(.{ .fg = .{ .ansi4 = .bright_green } }),
                .warn => tint.style(.{ .fg = .{ .ansi4 = .bright_yellow }, .bold = true }),
                .err => tint.style(.{ .fg = .{ .ansi4 = .bright_red }, .bold = true }),
            };
            const prefix = switch (level) {
                .debug => "DEBUG",
                .info => "INFO",
                .warn => "WARN",
                .err => "ERROR",
            };
            const app_style = tint.style(.{ .fg = .{ .ansi4 = .bright_cyan }, .bold = true });
            std.debug.print(
                "{s}HTTPX{s} {s}[{s}]{s} " ++ format ++ "\n",
                .{ app_style.toAnsi(), tint.reset, level_style.toAnsi(), prefix, tint.reset } ++ args,
            );
        }
    }

    /// Returns the effective server port (useful when `port_conflict = .increment`).
    pub fn listeningPort(self: *const Self) u16 {
        return self.config.port;
    }

    fn maxPortBindAttempts(self: *const Self) u16 {
        return if (self.config.port_conflict == .increment)
            @max(self.config.max_port_tries, 1)
        else
            1;
    }

    fn portCandidate(base: u16, attempt: u16) ?u16 {
        const candidate_u32 = @as(u32, base) + @as(u32, attempt);
        if (candidate_u32 > std.math.maxInt(u16)) return null;
        return @intCast(candidate_u32);
    }

    fn bindTcpListener(self: *Self, backlog: u31) !void {
        const attempts = self.maxPortBindAttempts();
        var attempt: u16 = 0;

        while (attempt < attempts) : (attempt += 1) {
            const candidate_port = portCandidate(self.config.port, attempt) orelse return error.PortRangeExhausted;
            const addr = try net.Address.parseIp(self.config.host, candidate_port);

            const listener = TcpListener.initWithBacklog(addr, backlog) catch |err| switch (err) {
                error.AddressInUse, error.BindFailed => {
                    if (self.config.port_conflict == .increment and attempt + 1 < attempts) {
                        continue;
                    }
                    return err;
                },
                else => return err,
            };

            self.listener = listener;
            const actual_addr = try self.listener.?.getLocalAddress();
            self.config.port = actual_addr.getPort();
            return;
        }

        return error.PortRangeExhausted;
    }

    fn bindUdpSocket(self: *Self) !void {
        const attempts = self.maxPortBindAttempts();
        var attempt: u16 = 0;

        while (attempt < attempts) : (attempt += 1) {
            const candidate_port = portCandidate(self.config.port, attempt) orelse return error.PortRangeExhausted;
            const addr = try net.Address.parseIp(self.config.host, candidate_port);

            var socket = try UdpSocket.createForAddress(addr);
            if (socket.bind(addr)) {
                if (self.config.request_timeout_ms > 0) {
                    socket.setRecvTimeout(self.config.request_timeout_ms) catch |err| {
                        socket.close();
                        return err;
                    };
                }

                self.udp_socket = socket;
                const actual_addr = try self.udp_socket.?.getLocalAddress();
                self.config.port = actual_addr.getPort();
                return;
            } else |err| {
                socket.close();
                if (self.config.port_conflict == .increment and attempt + 1 < attempts) {
                    continue;
                }
                return err;
            }
        }

        return error.PortRangeExhausted;
    }

    fn listenTcp(self: *Self) !void {
        if (self.listener == null) {
            const backlog_u32: u32 = @max(self.config.max_connections, 1);
            const backlog: u31 = @intCast(@min(backlog_u32, @as(u32, std.math.maxInt(u31))));
            try self.bindTcpListener(backlog);
        }
        self.running.store(true, .release);

        if (self.executor) |*e| {
            try e.start();
        }

        self.log(.info, "Server listening on {s}:{d}\n", .{ self.config.host, self.config.port });
        if (self.config.on_started) |hook| hook(self);

        try self.listenTcpAcceptLoop();
    }

    /// TCP accept loop -- accepts connections and dispatches to handler.
    /// Called from `listenTcp` (standalone) or from a background thread when
    /// running alongside HTTP/3.
    fn listenTcpAcceptLoop(self: *Self) !void {
        while (self.running.load(.acquire)) {
            // Wait for the listener socket to be readable (connection pending)
            // with a 500ms timeout so we can re-check self.running for clean
            // shutdown. On Windows, closesocket() from another thread may not
            // unblock a blocking accept().
            if (self.listener) |*l| {
                if (!l.socket.waitReadable(500)) continue;
            } else break;
            // Re-check after waitReadable — stop() may have nulled the
            // listener during the 500ms wait.
            if (!self.running.load(.acquire) or self.listener == null) break;
            const conn = self.listener.?.accept() catch {
                if (!self.running.load(.acquire)) break;
                continue;
            };

            self.dispatchToExecutor(conn.socket);
        }
    }

    fn listenHTTP3(self: *Self) !void {
        if (self.udp_socket == null) {
            try self.bindUdpSocket();
        }
        self.running.store(true, .release);

        self.log(.info, "Server listening (HTTP/3) on {s}:{d}\n", .{ self.config.host, self.config.port });

        try self.listenHTTP3AcceptLoop();
    }

    /// HTTP/3 UDP recv loop -- receives QUIC packets and dispatches to handler.
    /// Called from `listenHTTP3` (standalone) or from the current thread when
    /// running alongside TCP.
    fn listenHTTP3AcceptLoop(self: *Self) !void {
        var recv_buf: [64 * 1024]u8 = undefined;

        while (self.running.load(.acquire)) {
            const incoming = self.udp_socket.?.recvFrom(&recv_buf) catch |err| {
                if (!self.running.load(.acquire)) break;
                self.log(.err, "HTTP/3 recv error: {}\n", .{err});
                continue;
            };

            self.handleHTTP3Transaction(incoming.addr, recv_buf[0..incoming.n]) catch |err| {
                self.log(.err, "HTTP/3 handler error: {}\n", .{err});
            };
        }
    }

    /// Dispatches a socket connection to the executor thread pool, or handles
    /// it directly on the current thread when no executor is configured.
    fn dispatchToExecutor(self: *Self, socket: Socket) void {
        // Enforce connection limit with CAS loop to avoid TOCTOU race.
        while (true) {
            const current = self.active_conn_count.load(.acquire);
            if (current >= self.config.max_connections) {
                var s = socket;
                s.close();
                return;
            }
            if (self.active_conn_count.cmpxchgWeak(current, current + 1, .acq_rel, .monotonic) == null) {
                break;
            }
        }

        if (self.executor) |*e| {
            const ConnJob = struct {
                server: *Self,
                socket: Socket,
                fn run(ctx_ptr: ?*anyopaque) void {
                    const ctx: *@This() = @ptrCast(@alignCast(ctx_ptr.?));
                    ctx.server.handleConnection(ctx.socket) catch |err| {
                        switch (err) {
                            error.TlsConnectionTruncated, error.EndOfStream, error.ConnectionReset, error.RecvFailed, error.SendFailed, error.ReadFailed => {},
                            else => ctx.server.log(.err, "Handler error: {}\n", .{err}),
                        }
                    };
                    // Remove from executor tracking.
                    const io = defaultIo();
                    ctx.server.executor_conn_mutex.lock(io) catch unreachable;
                    for (ctx.server.executor_connections.items, 0..) |*s, i| {
                        if (s.handle == ctx.socket.handle) {
                            _ = ctx.server.executor_connections.orderedRemove(i);
                            break;
                        }
                    }
                    ctx.server.executor_conn_mutex.unlock(io);
                    var owned_socket = ctx.socket;
                    owned_socket.close();
                    _ = ctx.server.active_conn_count.fetchSub(1, .monotonic);
                    ctx.server.allocator.destroy(ctx);
                }
            };
            const job_ctx = self.allocator.create(ConnJob) catch {
                var s = socket;
                s.close();
                _ = self.active_conn_count.fetchSub(1, .monotonic);
                return;
            };
            job_ctx.* = .{
                .server = self,
                .socket = socket,
            };
            // Track in executor connections so stop() can close it.
            {
                const io = defaultIo();
                self.executor_conn_mutex.lock(io) catch unreachable;
                self.executor_connections.append(self.allocator, socket) catch {};
                self.executor_conn_mutex.unlock(io);
            }
            e.submit(.{
                .func = ConnJob.run,
                .context = job_ctx,
            }) catch |err| {
                self.log(.err, "Executor submission failed: {s}\n", .{@errorName(err)});
                {
                    const io = defaultIo();
                    self.executor_conn_mutex.lock(io) catch unreachable;
                    for (self.executor_connections.items, 0..) |*s, i| {
                        if (s.handle == socket.handle) {
                            _ = self.executor_connections.orderedRemove(i);
                            break;
                        }
                    }
                    self.executor_conn_mutex.unlock(io);
                }
                var s = socket;
                s.close();
                self.allocator.destroy(job_ctx);
                _ = self.active_conn_count.fetchSub(1, .monotonic);
            };
        } else {
            {
                const io = defaultIo();
                self.active_conn_mutex.lock(io) catch unreachable;
                self.active_connections.append(self.allocator, socket) catch {};
                self.active_conn_mutex.unlock(io);
            }
            self.handleConnection(socket) catch |err| {
                // TlsConnectionTruncated, EndOfStream, and ReadFailed are normal client
                // disconnections — not errors — don't pollute stderr with them.
                switch (err) {
                    error.TlsConnectionTruncated, error.EndOfStream, error.ConnectionReset, error.RecvFailed, error.SendFailed, error.ReadFailed => {},
                    else => self.log(.err, "Handler error: {}\n", .{err}),
                }
            };
            self.removeFromActive(socket);
            var owned_socket = socket;
            owned_socket.close();
        }
    }

    fn removeFromActive(self: *Self, socket: Socket) void {
        const io = defaultIo();
        self.active_conn_mutex.lock(io) catch unreachable;
        defer self.active_conn_mutex.unlock(io);
        var i: usize = 0;
        while (i < self.active_connections.items.len) {
            if (self.active_connections.items[i].handle == socket.handle) {
                _ = self.active_connections.swapRemove(i);
                break;
            }
            i += 1;
        }
        _ = self.active_conn_count.fetchSub(1, .monotonic);
    }

    fn isValidHttpToken(value: []const u8) bool {
        if (value.len == 0) return false;
        for (value) |c| {
            if (!std.ascii.isAlphanumeric(c) and
                c != '!' and c != '#' and c != '$' and c != '%' and c != '&' and
                c != '\'' and c != '*' and c != '+' and c != '-' and c != '.' and
                c != '^' and c != '_' and c != '`' and c != '|' and c != '~')
            {
                return false;
            }
        }
        return true;
    }

    fn isValidHttp2HeaderName(name: []const u8) bool {
        if (!isValidHttpToken(name)) return false;
        for (name) |c| {
            if (c >= 'A' and c <= 'Z') return false;
        }
        return true;
    }

    /// Parses pseudo-headers (:method, :path, :scheme, :authority) from a
    /// decoded header block and appends regular headers to `request_headers`.
    fn parseHeaders(
        self: *Self,
        comptime HeaderT: type,
        entries: []const HeaderT,
        request_headers: *Headers,
        method: *[]const u8,
        method_owned: *bool,
        path: *[]const u8,
        path_owned: *bool,
        scheme: *[]const u8,
        scheme_owned: *bool,
        authority: *?[]const u8,
        authority_owned: *bool,
    ) !void {
        var saw_regular_header = false;
        for (entries) |h| {
            if (h.name.len > 0 and h.name[0] == ':') {
                if (saw_regular_header) return error.ProtocolError;
                if (mem.eql(u8, h.name, ":method")) {
                    if (method_owned.*) return error.ProtocolError;
                    if (!isValidHttpToken(h.value)) return error.ProtocolError;
                    method.* = try self.allocator.dupe(u8, h.value);
                    method_owned.* = true;
                } else if (mem.eql(u8, h.name, ":path")) {
                    if (path_owned.*) return error.ProtocolError;
                    path.* = try self.allocator.dupe(u8, h.value);
                    path_owned.* = true;
                } else if (mem.eql(u8, h.name, ":scheme")) {
                    if (scheme_owned.*) return error.ProtocolError;
                    scheme.* = try self.allocator.dupe(u8, h.value);
                    scheme_owned.* = true;
                } else if (mem.eql(u8, h.name, ":authority")) {
                    if (authority_owned.*) return error.ProtocolError;
                    authority.* = try self.allocator.dupe(u8, h.value);
                    authority_owned.* = true;
                } else return error.ProtocolError;
                continue;
            }

            saw_regular_header = true;
            if (!isValidHttp2HeaderName(h.name)) return error.ProtocolError;
            if (common.isConnectionSpecificHeader(h.name)) return error.ProtocolError;
            if (mem.eql(u8, h.name, "te") and !std.ascii.eqlIgnoreCase(mem.trim(u8, h.value, " \t"), "trailers")) {
                return error.ProtocolError;
            }
            try request_headers.append(h.name, h.value);
        }
    }

    /// Stops the server.
    pub fn stop(self: *Self) void {
        if (self.config.on_stopping) |hook| hook(self);

        // Phase 1: Stop accepting new connections.
        self.running.store(false, .release);
        if (self.listener) |*l| {
            l.deinit();
            self.listener = null;
        }
        if (self.udp_socket) |*u| {
            u.close();
            self.udp_socket = null;
        }
        if (self.unix_listener) |*u| {
            var sock = Socket.fromHandle(u.fd);
            sock.shutdownBoth() catch {};
            u.deinit();
            self.unix_listener = null;
        }

        // Phase 2: Wait for active connections to drain (with timeout).
        // Default 5s drain timeout when none configured, so we never spin forever.
        const effective_timeout_ms: u64 = if (self.config.shutdown_timeout_ms > 0)
            self.config.shutdown_timeout_ms
        else
            5000;
        const drain_deadline_ms: u64 = @intCast(@max(0, common.nowMillis() +| @as(i64, @intCast(@min(effective_timeout_ms, @as(u64, std.math.maxInt(i64)))))));

        while (self.active_conn_count.load(.acquire) > 0) {
            const now_ms: u64 = @intCast(@max(0, common.nowMillis()));
            if (now_ms >= drain_deadline_ms) break;
            const io = defaultIo();
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .real) catch {};
        }

        // Phase 3: Force-close any remaining connections.
        {
            const io = defaultIo();
            self.active_conn_mutex.lock(io) catch unreachable;
            for (self.active_connections.items) |*s| {
                s.shutdownBoth() catch {};
            }
            self.active_conn_mutex.unlock(io);
        }

        // Interrupt executor-tracked sockets; each connection handler remains
        // the sole close owner.
        {
            const io = defaultIo();
            self.executor_conn_mutex.lock(io) catch unreachable;
            for (self.executor_connections.items) |*s| {
                s.shutdownBoth() catch {};
            }
            self.executor_conn_mutex.unlock(io);
        }

        // Join the UDP thread if it was spawned.
        if (self.udp_thread) |t| {
            t.join();
            self.udp_thread = null;
        }
        if (self.executor) |*e| {
            e.stop();
        }
        if (self.config.on_stopped) |hook| hook(self);
    }

    fn listenUnix(self: *Self, path: []const u8) !void {
        if (self.unix_listener == null) {
            const unix_mod = @import("../net/unix.zig");
            self.unix_listener = try unix_mod.UnixListener.init(path);
        }
        self.running.store(true, .release);

        if (self.executor) |*e| {
            try e.start();
        }

        self.log(.info, "Server listening on Unix socket: {s}\n", .{path});
        if (self.config.on_started) |hook| hook(self);

        while (self.running.load(.acquire)) {
            // Re-check before accept — stop() may have nulled the listener.
            if (self.unix_listener == null) break;
            const conn = self.unix_listener.?.accept() catch |err| {
                if (!self.running.load(.acquire)) break;
                self.log(.err, "Unix Accept error: {}\n", .{err});
                continue;
            };

            const socket_wrapper = Socket.fromHandle(conn.socket.fd);
            self.dispatchToExecutor(socket_wrapper);
        }
    }

    /// Handles a single connection.
    fn handleConnection(self: *Self, socket: Socket) !void {
        var sock = socket;

        if (self.config.tls_enabled) {
            // Use config.tls_alpn_protocols when set (non-default), otherwise
            // build dynamically from enabled protocols.
            const alpn_protos: []const []const u8 = if (self.config.http3_enabled and self.config.http2_enabled)
                &.{ "h3", "h2", "http/1.1" }
            else if (self.config.http2_enabled)
                &.{ "h2", "http/1.1" }
            else
                &.{"http/1.1"};

            // Load TLS cert/key if not already loaded (with mutex to prevent double-init)
            if (self.server_tls_config == null) {
                const io = defaultIo();
                self.tls_init_mutex.lock(io) catch unreachable;
                defer self.tls_init_mutex.unlock(io);
                if (self.server_tls_config == null) {
                    if (self.config.tls_cert_path) |cert_path| {
                        if (self.config.tls_key_path) |key_path| {
                            self.server_tls_config = tls_mod.loadServerTLSConfig(self.allocator, cert_path, key_path) catch |err| {
                                self.log(.err, "Failed to load TLS cert/key: {}\n", .{err});
                                return;
                            };
                        }
                    }
                }
            }

            // Set send/recv timeouts so TLS operations (including closeNotify)
            // don't block indefinitely on Linux when the peer has disconnected.
            if (self.config.write_timeout_ms > 0) {
                sock.setSendTimeout(self.config.write_timeout_ms) catch {};
            } else {
                sock.setSendTimeout(5000) catch {};
            }
            if (self.config.keep_alive_timeout_ms > 0) {
                sock.setRecvTimeout(self.config.keep_alive_timeout_ms) catch {};
            } else {
                sock.setRecvTimeout(5000) catch {};
            }

            var tls_conn = tls_mod.acceptServer(self.allocator, &sock, alpn_protos, self.server_tls_config) catch |err| {
                self.log(.err, "TLS accept failed: {}\n", .{err});
                return;
            };
            defer tls_conn.closeNotify();

            const alpn_protocol = tls_conn.negotiatedAlpn() orelse "http/1.1";

            // Use the alpn module's helper which handles h3 draft versions.
            if (alpn.isHTTP3(alpn_protocol) and self.config.http3_enabled) {
                // HTTP/3 over TLS typically runs over QUIC (UDP), not TCP.
                // If the server receives an h3 ALPN over TCP, it means the
                // client expects QUIC.  Send an ALPN alert and close.
                self.log(.warn, "Client negotiated h3 over TCP; HTTP/3 requires QUIC/UDP\n", .{});
                tls_conn.sendAlert(.fatal, .protocol_version);
                return;
            }
            if (alpn.isHTTP2(alpn_protocol) and self.config.http2_enabled) {
                return self.handleHTTP2WithTLS(&tls_conn);
            }
            return self.handleHTTP1WithTLS(&tls_conn);
        }

        if (self.config.http2_enabled) {
            // Read the first bytes to detect the HTTP/2 connection preface.
            // If the client sends the 24-byte preface, handle as HTTP/2;
            // otherwise those bytes are the start of an HTTP/1.1 request.
            var probe: [http.HTTP2_PREFACE.len]u8 = undefined;
            var total: usize = 0;
            var preface_context = IoContext.init(.{
                .phase_deadline = if (self.config.request_timeout_ms > 0)
                    Deadline.afterMs(self.config.request_timeout_ms)
                else
                    null,
            });
            while (total < probe.len) {
                const n = try sock.recvWithContext(probe[total..], &preface_context);
                if (n == 0) return;
                total += n;
                if (!mem.eql(
                    u8,
                    probe[0..total],
                    http.HTTP2_PREFACE[0..total],
                )) {
                    return self.handleHttp1WithPrefix(sock, probe[0..total]);
                }
            }

            return self.handleHTTP2Connection(sock);
        }

        return self.handleHttp1Connection(sock);
    }

    /// Handles an HTTP/1.1 connection from scratch (no prefix bytes).
    fn handleHttp1Connection(self: *Self, sock: Socket) !void {
        return self.handleHttp1WithPrefix(sock, &.{});
    }

    /// Handles an HTTP/1.1 connection where `prefix` bytes have already been
    /// read from the socket (e.g. during HTTP/2 preface detection).
    fn handleHttp1WithPrefix(self: *Self, socket: Socket, prefix: []const u8) !void {
        var sock = socket;
        var first_request = true;
        while (self.running.load(.acquire)) {
            const timeout_ms = if (first_request) self.config.request_timeout_ms else self.config.keep_alive_timeout_ms;
            if (timeout_ms > 0) {
                try sock.setRecvTimeout(timeout_ms);
            }

            var buffer: [8192]u8 = undefined;
            var parser = Parser.init(self.allocator);
            parser.max_header_size = self.config.max_header_size;
            parser.max_headers = self.config.max_headers;
            parser.max_body_size = self.config.max_body_size;
            defer parser.deinit();

            // If prefix bytes were provided, feed them first.
            if (!first_request or prefix.len == 0) {
                // No prefix or subsequent request -- normal read path.
            } else if (prefix.len > 0) {
                _ = try parser.feed(prefix);
                if (parser.getBody().len > self.config.max_body_size) {
                    try self.sendError(&sock, 413);
                    return;
                }
            }

            while (!parser.isComplete()) {
                const n = sock.recv(&buffer) catch |err| {
                    // Recv timeout or read failure during keep-alive idle wait is normal —
                    // the client simply disconnected or didn't send another request in time.
                    if (err == error.TimedOut or err == error.ReadFailed) return;
                    return err;
                };
                if (n == 0) {
                    return;
                }
                _ = try parser.feed(buffer[0..n]);
                if (parser.getBody().len > self.config.max_body_size) {
                    try self.sendError(&sock, 413);
                    return;
                }
            }

            var req = try Request.init(
                self.allocator,
                parser.method orelse .GET,
                parser.path orelse "/",
            );
            defer req.deinit();
            req.version = parser.version;
            if (parser.custom_method) |method| try req.setCustomMethod(method);

            for (parser.headers.entries.items) |h| {
                try req.headers.append(h.name, h.value);
            }

            if (parser.getBody().len > 0) {
                req.body = parser.getBody();
            }

            var response = self.executeServerRequest(&req, &sock, null) catch |err| {
                self.log(.err, "Handler error: {}\n", .{err});
                return self.sendError(&sock, status_mod.StatusCode.INTERNAL_SERVER_ERROR);
            };

            defer response.deinit();

            // If handler streamed the response directly, skip normal formatting.
            if (response.streaming_done) return;

            const request_wants_keep_alive = req.headers.isKeepAlive(req.version);
            const keep_alive = self.config.keep_alive and request_wants_keep_alive;
            if (!keep_alive) {
                try response.headers.set(HeaderName.CONNECTION, "close");
            }

            try self.ensureContentLengthHeader(&response);

            const formatted = try http.formatResponse(&response, self.allocator);
            defer self.allocator.free(formatted);

            // Set write timeout for response sending.
            if (self.config.write_timeout_ms > 0) {
                try sock.setSendTimeout(self.config.write_timeout_ms);
            }
            try sock.sendAll(formatted);

            if (!keep_alive) return;
            first_request = false;
        }
    }

    /// Handles an HTTP/1.1 connection over TLS.
    fn handleHTTP1WithTLS(self: *Self, tls_conn: *tls_mod.Connection) !void {
        var first_request = true;
        while (self.running.load(.acquire)) {
            const timeout_ms = if (first_request) self.config.request_timeout_ms else self.config.keep_alive_timeout_ms;
            // Idle-timeout window starts NOW for this request; last_activity_ms
            // is shared server state and may be stale from a prior connection.
            self.last_activity_ms = common.nowMillis();

            var parser = Parser.init(self.allocator);
            parser.max_header_size = self.config.max_header_size;
            parser.max_headers = self.config.max_headers;
            parser.max_body_size = self.config.max_body_size;
            defer parser.deinit();

            while (!parser.isComplete()) {
                // Enforce timeout by checking elapsed time.
                if (timeout_ms > 0) {
                    const elapsed = common.nowMillis() -| self.last_activity_ms;
                    if (elapsed > @as(i64, @intCast(timeout_ms))) {
                        return error.TimedOut;
                    }
                }

                var read_buf: [8192]u8 = undefined;
                const n = tls_conn.read(&read_buf) catch |err| {
                    self.log(.err, "TLS read error: {}\n", .{err});
                    return;
                };
                if (n == 0) {
                    return;
                }
                self.last_activity_ms = common.nowMillis();
                _ = try parser.feed(read_buf[0..n]);
                if (parser.getBody().len > self.config.max_body_size) {
                    try self.sendTLSError(tls_conn, 413);
                    return;
                }
            }

            var req = try Request.init(
                self.allocator,
                parser.method orelse .GET,
                parser.path orelse "/",
            );
            defer req.deinit();
            req.version = parser.version;
            if (parser.custom_method) |method| try req.setCustomMethod(method);

            for (parser.headers.entries.items) |h| {
                try req.headers.append(h.name, h.value);
            }

            if (parser.getBody().len > 0) {
                req.body = parser.getBody();
            }

            var response = self.executeServerRequest(&req, null, tls_conn) catch |err| {
                self.log(.err, "Handler error: {}\n", .{err});
                return self.sendTLSError(tls_conn, status_mod.StatusCode.INTERNAL_SERVER_ERROR);
            };

            defer response.deinit();

            // If handler streamed the response directly, skip normal formatting.
            if (response.streaming_done) return;

            const request_wants_keep_alive = req.headers.isKeepAlive(req.version);
            const keep_alive = self.config.keep_alive and request_wants_keep_alive;
            if (!keep_alive) {
                try response.headers.set(HeaderName.CONNECTION, "close");
            }

            try self.ensureContentLengthHeader(&response);

            const formatted = try http.formatResponse(&response, self.allocator);
            defer self.allocator.free(formatted);

            tls_conn.writeAll(formatted) catch |err| {
                self.log(.err, "TLS write error: {}\n", .{err});
                return;
            };

            if (!keep_alive) return;
            first_request = false;
        }
    }

    /// Per-stream state for HTTP/2 concurrent stream processing.
    const H2ServerStreamContext = struct {
        stream_id: u31,
        request_headers: Headers,
        request_body: std.ArrayList(u8),
        method_raw: []const u8,
        method_owned: bool,
        path_raw: []const u8,
        path_owned: bool,
        scheme_raw: []const u8,
        scheme_owned: bool,
        authority_raw: ?[]const u8,
        authority_owned: bool,
        pending_headers_block: std.ArrayList(u8),
        pending_headers_flags: u8,
        pending_is_trailers: bool,
        waiting_continuation: bool,
        header_deadline: ?Deadline,
        initial_headers_parsed: bool,
        headers_complete: bool,
        expected_content_length: ?u64,
        received_body_bytes: u64,
        done: bool,

        fn init(allocator: Allocator, stream_id: u31) @This() {
            return .{
                .stream_id = stream_id,
                .request_headers = Headers.init(allocator),
                .request_body = .empty,
                .method_raw = "",
                .method_owned = false,
                .path_raw = "",
                .path_owned = false,
                .scheme_raw = "",
                .scheme_owned = false,
                .authority_raw = null,
                .authority_owned = false,
                .pending_headers_block = .empty,
                .pending_headers_flags = 0,
                .pending_is_trailers = false,
                .waiting_continuation = false,
                .header_deadline = null,
                .initial_headers_parsed = false,
                .headers_complete = false,
                .expected_content_length = null,
                .received_body_bytes = 0,
                .done = false,
            };
        }

        fn deinit(self: *@This(), allocator: Allocator) void {
            self.request_headers.deinit();
            self.request_body.deinit(allocator);
            if (self.method_owned) allocator.free(self.method_raw);
            if (self.path_owned) allocator.free(self.path_raw);
            if (self.scheme_owned) allocator.free(self.scheme_raw);
            if (self.authority_owned and self.authority_raw != null) allocator.free(self.authority_raw.?);
            self.pending_headers_block.deinit(allocator);
        }
    };

    const H2ServerContextReader = struct {
        const Source = union(enum) {
            socket: *Socket,
            tls: *tls_mod.Connection,
        };

        source: Source,
        context: *const IoContext,

        fn read(context_ptr: *anyopaque, output: []u8) !usize {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            return switch (self.source) {
                .socket => |socket| socket.recvWithContext(output, self.context),
                .tls => |connection| connection.readWithContext(output, self.context),
            };
        }

        fn anyReader(self: *@This()) io_util.AnyReader {
            return .{ .context = self, .readFn = read };
        }
    };

    /// Handles an HTTP/2 connection over TLS.
    fn validateHTTP2Preface(preface: []const u8) !void {
        if (!mem.eql(u8, preface, http.HTTP2_PREFACE)) return error.ProtocolError;
    }

    fn handleHTTP2WithTLS(self: *Self, tls_conn: *tls_mod.Connection) !void {
        var preface: [http.HTTP2_PREFACE.len]u8 = undefined;
        try tls_conn.reader().readNoEof(&preface);
        try validateHTTP2Preface(&preface);
        var frame_context = IoContext.init(.{});
        var contextual_reader = H2ServerContextReader{
            .source = .{ .tls = tls_conn },
            .context = &frame_context,
        };
        var conn = http.HTTP2Connection.init(
            self.allocator,
            contextual_reader.anyReader(),
            tls_conn.writer(),
        );
        try self.handleHTTP2Frames(&conn, true, &frame_context);
    }

    /// Handles an HTTP/2 connection over plain TCP.
    fn handleHTTP2Connection(self: *Self, socket: Socket) !void {
        var sock = socket;
        if (self.config.request_timeout_ms > 0) {
            try sock.setRecvTimeout(self.config.request_timeout_ms);
        }
        if (self.config.write_timeout_ms > 0) {
            try sock.setSendTimeout(self.config.write_timeout_ms);
        }
        var frame_context = IoContext.init(.{});
        var contextual_reader = H2ServerContextReader{
            .source = .{ .socket = &sock },
            .context = &frame_context,
        };
        var conn = http.HTTP2Connection.init(
            self.allocator,
            contextual_reader.anyReader(),
            sock.writer(),
        );
        try self.handleHTTP2Frames(&conn, false, &frame_context);
        sock.shutdownWrite() catch {};
        sleepMs(25);
    }

    fn appendHTTP2HeaderFragment(
        self: *Self,
        destination: *std.ArrayList(u8),
        payload: []const u8,
        flags: u8,
    ) !void {
        var offset: usize = 0;
        var padding: usize = 0;
        if ((flags & 0x08) != 0) {
            if (payload.len == 0) return error.ProtocolError;
            padding = payload[0];
            offset = 1;
        }
        if ((flags & 0x20) != 0) {
            if (payload.len - offset < 5) return error.ProtocolError;
            offset += 5;
        }
        if (padding > payload.len - offset) return error.ProtocolError;
        const fragment = payload[offset .. payload.len - padding];
        if (destination.items.len > self.config.max_header_size or
            fragment.len > self.config.max_header_size - destination.items.len)
        {
            return error.HeaderTooLarge;
        }
        try destination.appendSlice(self.allocator, fragment);
    }

    fn applyHTTP2SendWindowUpdate(
        stream_manager: *h2stream.StreamManager,
        header: http.HTTP2FrameHeader,
        payload: []const u8,
    ) !void {
        if (payload.len != 4) return error.ProtocolError;
        const increment = try h2stream.parseWindowUpdatePayload(payload);
        if (header.stream_id == 0) {
            try stream_manager.updateConnectionSendWindow(@intCast(increment));
            return;
        }
        const stream = stream_manager.getStream(header.stream_id) orelse
            return error.ProtocolError;
        if (stream.state == .closed) return;
        try stream.updateSendWindow(@intCast(increment));
    }

    fn isImplicitlyClosedClientStream(stream_id: u31, last_client_stream_id: u31) bool {
        return stream_id != 0 and
            (stream_id & 1) == 1 and
            stream_id < last_client_stream_id;
    }

    fn pumpHTTP2SendWindow(
        self: *Self,
        conn: *http.HTTP2Connection,
        stream_manager: *h2stream.StreamManager,
        stream_id: u31,
        frame_context: *IoContext,
        send_wait_deadline: ?Deadline,
        pending_frames: *std.ArrayList(http.HTTP2Connection.Frame),
        pending_frame_bytes: *usize,
        queued_continuation_stream: *?u31,
        last_client_stream_id: u31,
    ) !void {
        const previous_deadline = frame_context.phase_deadline;
        frame_context.setPhaseDeadline(send_wait_deadline);
        var frame = conn.readFrame(self.allocator, conn.settings.max_frame_size) catch |err| {
            frame_context.setPhaseDeadline(previous_deadline);
            return err;
        };
        frame_context.setPhaseDeadline(previous_deadline);
        var frame_owned = true;
        defer if (frame_owned) frame.deinit(self.allocator);
        if (queued_continuation_stream.*) |required_stream| {
            if (frame.header.frame_type != .continuation or
                frame.header.stream_id != required_stream)
            {
                return error.ProtocolError;
            }
        } else if (frame.header.frame_type == .continuation) {
            return error.ProtocolError;
        }
        switch (frame.header.frame_type) {
            .window_update => {
                if (frame.header.stream_id != 0 and
                    stream_manager.getStream(frame.header.stream_id) == null and
                    isImplicitlyClosedClientStream(
                        frame.header.stream_id,
                        last_client_stream_id,
                    ))
                {
                    _ = try h2stream.parseWindowUpdatePayload(frame.payload);
                } else {
                    try applyHTTP2SendWindowUpdate(
                        stream_manager,
                        frame.header,
                        frame.payload,
                    );
                }
            },
            .settings => {
                if (frame.header.stream_id != 0) return error.ProtocolError;
                if ((frame.header.flags & 0x01) != 0) {
                    if (frame.payload.len != 0) return error.ProtocolError;
                    return;
                }
                var peer_settings = conn.peer_settings;
                try http.applySettingsPayloadForPeer(&peer_settings, frame.payload, .client);
                try stream_manager.applyPeerSettings(peer_settings);
                conn.peer_settings = peer_settings;
                try conn.writeFrame(.{
                    .length = 0,
                    .frame_type = .settings,
                    .flags = 0x01,
                    .stream_id = 0,
                }, &.{});
            },
            .ping => {
                if (frame.header.stream_id != 0 or frame.payload.len != 8) {
                    return error.ProtocolError;
                }
                if ((frame.header.flags & 0x01) == 0) {
                    try conn.writeFrame(.{
                        .length = 8,
                        .frame_type = .ping,
                        .flags = 0x01,
                        .stream_id = 0,
                    }, frame.payload);
                }
            },
            .rst_stream => {
                if (frame.header.stream_id == 0 or frame.payload.len != 4) {
                    return error.ProtocolError;
                }
                if (frame.header.stream_id == stream_id) {
                    if (stream_manager.getStream(stream_id)) |stream| stream.reset();
                    return error.StreamReset;
                }
                if (stream_manager.getStream(frame.header.stream_id)) |other_stream| {
                    if (other_stream.state == .closed) return;
                } else if (isImplicitlyClosedClientStream(
                    frame.header.stream_id,
                    last_client_stream_id,
                )) {
                    return;
                }
                try queueHTTP2Frame(
                    self,
                    pending_frames,
                    pending_frame_bytes,
                    frame,
                );
                frame_owned = false;
            },
            .goaway => return error.GoAway,
            .headers, .continuation, .data => {
                if (frame.header.frame_type == .data) {
                    const debit = std.math.cast(i32, frame.payload.len) orelse
                        return error.FlowControlError;
                    if (debit > stream_manager.connection_recv_window) {
                        return error.FlowControlError;
                    }
                    stream_manager.connection_recv_window -= debit;
                }
                try queueHTTP2Frame(
                    self,
                    pending_frames,
                    pending_frame_bytes,
                    frame,
                );
                frame_owned = false;
                if (frame.header.frame_type == .headers and
                    (frame.header.flags & 0x04) == 0)
                {
                    queued_continuation_stream.* = frame.header.stream_id;
                } else if (frame.header.frame_type == .continuation and
                    (frame.header.flags & 0x04) != 0)
                {
                    queued_continuation_stream.* = null;
                }
            },
            .push_promise => return error.ProtocolError,
            // PRIORITY and unknown extension frames are connection-neutral.
            else => {},
        }
    }

    fn queueHTTP2Frame(
        self: *Self,
        pending_frames: *std.ArrayList(http.HTTP2Connection.Frame),
        pending_frame_bytes: *usize,
        frame: http.HTTP2Connection.Frame,
    ) !void {
        const max_pending_bytes = 256 * 1024;
        if (pending_frames.items.len >= 1024 or
            frame.payload.len > max_pending_bytes -| pending_frame_bytes.*)
        {
            return error.EnhanceYourCalm;
        }
        try pending_frames.append(self.allocator, frame);
        pending_frame_bytes.* += frame.payload.len;
    }

    fn requestContentLength(headers: *const Headers) !?u64 {
        var expected: ?u64 = null;
        for (headers.entries.items) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.name, HeaderName.CONTENT_LENGTH)) continue;
            var values = mem.splitScalar(u8, entry.value, ',');
            var saw_value = false;
            while (values.next()) |raw| {
                const value = mem.trim(u8, raw, " \t");
                if (value.len == 0) return error.InvalidContentLength;
                for (value) |byte| {
                    if (byte < '0' or byte > '9') return error.InvalidContentLength;
                }
                const parsed = std.fmt.parseInt(u64, value, 10) catch
                    return error.InvalidContentLength;
                if (expected) |existing| {
                    if (existing != parsed) return error.InvalidContentLength;
                } else {
                    expected = parsed;
                }
                saw_value = true;
            }
            if (!saw_value) return error.InvalidContentLength;
        }
        return expected;
    }

    fn enforceContinuation(required_stream: ?u31, header: http.HTTP2FrameHeader) !void {
        const stream_id = required_stream orelse return;
        if (header.frame_type != .continuation or header.stream_id != stream_id) {
            return error.ProtocolError;
        }
    }

    fn validateRequestBodyLength(ctx: *const H2ServerStreamContext) !void {
        const expected = ctx.expected_content_length orelse return;
        if (ctx.received_body_bytes < expected) return error.RequestBodyUnderrun;
        if (ctx.received_body_bytes > expected) return error.RequestBodyOverrun;
    }

    fn validateRequestTrailers(comptime HeaderT: type, entries: []const HeaderT) !void {
        for (entries) |entry| {
            if (entry.name.len == 0 or entry.name[0] == ':' or
                !isValidHttp2HeaderName(entry.name) or
                common.isConnectionSpecificHeader(entry.name) or
                std.ascii.eqlIgnoreCase(entry.name, HeaderName.CONTENT_LENGTH) or
                std.ascii.eqlIgnoreCase(entry.name, HeaderName.HOST))
            {
                return error.ProtocolError;
            }
        }
    }

    /// Common HTTP/2 frame processing loop for both TLS and plain TCP connections.
    /// Supports concurrent streams: processes each stream's request/response before
    /// moving to the next. Sends GOAWAY only after all streams complete.
    fn handleHTTP2Frames(
        self: *Self,
        conn: *http.HTTP2Connection,
        is_tls: bool,
        frame_context: *IoContext,
    ) !void {
        const local_settings = http.HTTP2Connection.HTTP2ConnectionSettings{
            .header_table_size = self.config.http2_settings.header_table_size,
            .enable_push = false,
            .max_concurrent_streams = self.config.http2_settings.max_concurrent_streams,
            .initial_window_size = self.config.http2_settings.initial_window_size,
            .max_frame_size = self.config.http2_settings.max_frame_size,
            .max_header_list_size = self.config.http2_settings.max_header_list_size,
        };
        if (local_settings.initial_window_size > 0x7fff_ffff or
            local_settings.max_frame_size < 16_384 or
            local_settings.max_frame_size > 16_777_215)
        {
            return error.InvalidHTTP2Settings;
        }
        conn.settings = local_settings;

        var settings_payload = std.ArrayList(u8).empty;
        defer settings_payload.deinit(self.allocator);
        try http.encodeSettingsPayloadForRole(local_settings, self.allocator, &settings_payload, .server);
        try conn.writeFrame(.{
            .length = @intCast(settings_payload.items.len),
            .frame_type = .settings,
            .flags = 0,
            .stream_id = 0,
        }, settings_payload.items);

        var stream_manager = h2stream.StreamManager.init(self.allocator, false);
        defer stream_manager.deinit();
        stream_manager.hpack_decoder.setMaxAllowedTableSize(local_settings.header_table_size);

        var contexts = std.ArrayList(H2ServerStreamContext).empty;
        defer {
            for (contexts.items) |*ctx| ctx.deinit(self.allocator);
            contexts.deinit(self.allocator);
        }
        var context_map = std.AutoHashMap(u31, usize).init(self.allocator);
        defer context_map.deinit();
        var pending_frames = std.ArrayList(http.HTTP2Connection.Frame).empty;
        defer {
            for (pending_frames.items) |*pending| pending.deinit(self.allocator);
            pending_frames.deinit(self.allocator);
        }
        var pending_frame_bytes: usize = 0;
        var queued_continuation_stream: ?u31 = null;
        var closed_stream_order = std.ArrayList(u31).empty;
        defer closed_stream_order.deinit(self.allocator);

        var continuation_stream: ?u31 = null;
        var all_done = false;
        var processed_this_iteration = false;
        var last_client_stream_id: u31 = 0;
        var last_processed_stream_id: u31 = 0;
        var received_initial_settings = false;

        const max_frame_payload: usize = local_settings.max_frame_size;
        const default_scheme: []const u8 = if (is_tls) "https" else "http";

        while (!all_done) {
            var incoming_frame_deadline: ?Deadline = null;
            var frame_from_queue = false;
            var frame = if (pending_frames.items.len > 0) blk: {
                const queued = pending_frames.orderedRemove(0);
                pending_frame_bytes -= queued.payload.len;
                frame_from_queue = true;
                break :blk queued;
            } else blk: {
                const frame_deadline = if (continuation_stream) |stream_id|
                    contexts.items[context_map.get(stream_id) orelse return error.ProtocolError].header_deadline
                else if (self.config.request_timeout_ms > 0)
                    Deadline.afterMs(self.config.request_timeout_ms)
                else
                    null;
                incoming_frame_deadline = frame_deadline;
                const previous_deadline = frame_context.phase_deadline;
                frame_context.setPhaseDeadline(frame_deadline);
                const incoming = conn.readFrame(self.allocator, max_frame_payload) catch |err| {
                    frame_context.setPhaseDeadline(previous_deadline);
                    return err;
                };
                frame_context.setPhaseDeadline(previous_deadline);
                break :blk incoming;
            };
            defer frame.deinit(self.allocator);

            processed_this_iteration = false;
            if (!received_initial_settings and
                (frame.header.frame_type != .settings or (frame.header.flags & 0x01) != 0))
            {
                return error.ProtocolError;
            }
            try enforceContinuation(continuation_stream, frame.header);
            switch (frame.header.frame_type) {
                .settings => {
                    if (frame.header.stream_id != 0) return error.ProtocolError;
                    if ((frame.header.flags & 0x01) == 0) {
                        var parsed_settings = conn.peer_settings;
                        try http.applySettingsPayloadForPeer(&parsed_settings, frame.payload, .client);
                        try stream_manager.applyPeerSettings(parsed_settings);
                        conn.peer_settings = parsed_settings;
                        received_initial_settings = true;
                        try conn.writeFrame(.{
                            .length = 0,
                            .frame_type = .settings,
                            .flags = 0x01,
                            .stream_id = 0,
                        }, &.{});
                    } else if (frame.payload.len != 0) {
                        return error.ProtocolError;
                    }
                },
                .ping => {
                    if (frame.header.stream_id != 0 or frame.payload.len != 8) return error.ProtocolError;
                    if ((frame.header.flags & 0x01) == 0) {
                        try conn.writeFrame(.{
                            .length = 8,
                            .frame_type = .ping,
                            .flags = 0x01,
                            .stream_id = 0,
                        }, frame.payload);
                    }
                },
                .headers => {
                    if (frame.header.stream_id == 0) return error.ProtocolError;

                    if (continuation_stream != null) return error.ProtocolError;

                    const stream_id = frame.header.stream_id;
                    var ctx = if (context_map.get(stream_id)) |idx| blk: {
                        if (contexts.items[idx].headers_complete or
                            contexts.items[idx].waiting_continuation)
                        {
                            return error.ProtocolError;
                        }
                        if ((frame.header.flags & 0x01) == 0) return error.ProtocolError;
                        break :blk &contexts.items[idx];
                    } else blk: {
                        if ((stream_id & 1) == 0 or stream_id <= last_client_stream_id) {
                            return error.ProtocolError;
                        }
                        if (contexts.items.len >= local_settings.max_concurrent_streams) {
                            return error.RefusedStream;
                        }
                        last_client_stream_id = stream_id;
                        const remote_stream = try stream_manager.getOrCreateStream(stream_id);
                        remote_stream.recv_window = @intCast(local_settings.initial_window_size);
                        remote_stream.send_window = @intCast(stream_manager.peer_settings.initial_window_size);
                        try remote_stream.open();
                        try contexts.append(self.allocator, H2ServerStreamContext.init(self.allocator, stream_id));
                        errdefer {
                            contexts.items[contexts.items.len - 1].deinit(self.allocator);
                            _ = contexts.pop();
                        }
                        try context_map.put(stream_id, contexts.items.len - 1);
                        break :blk &contexts.items[contexts.items.len - 1];
                    };
                    ctx.header_deadline = incoming_frame_deadline orelse
                        if (self.config.request_timeout_ms > 0)
                            Deadline.afterMs(self.config.request_timeout_ms)
                        else
                            null;

                    if ((frame.header.flags & 0x04) != 0) {
                        const parsed = try h2stream.parseHeadersFramePayloadWithLimit(
                            &stream_manager,
                            frame.payload,
                            frame.header.flags,
                            self.allocator,
                            local_settings.max_header_list_size,
                        );
                        defer {
                            for (parsed.headers) |header| {
                                self.allocator.free(header.name);
                                self.allocator.free(header.value);
                            }
                            self.allocator.free(parsed.headers);
                        }

                        if (ctx.initial_headers_parsed) {
                            try validateRequestTrailers(@TypeOf(parsed.headers[0]), parsed.headers);
                        } else {
                            try self.parseHeaders(
                                @TypeOf(parsed.headers[0]),
                                parsed.headers,
                                &ctx.request_headers,
                                &ctx.method_raw,
                                &ctx.method_owned,
                                &ctx.path_raw,
                                &ctx.path_owned,
                                &ctx.scheme_raw,
                                &ctx.scheme_owned,
                                &ctx.authority_raw,
                                &ctx.authority_owned,
                            );
                            ctx.expected_content_length = try requestContentLength(&ctx.request_headers);
                            ctx.initial_headers_parsed = true;
                        }

                        if ((frame.header.flags & 0x01) != 0) {
                            ctx.headers_complete = true;
                            stream_manager.getStream(stream_id).?.receiveEndStream();
                        }
                        ctx.header_deadline = null;
                    } else {
                        ctx.pending_headers_flags = frame.header.flags;
                        ctx.pending_is_trailers = ctx.initial_headers_parsed;
                        try self.appendHTTP2HeaderFragment(
                            &ctx.pending_headers_block,
                            frame.payload,
                            frame.header.flags,
                        );
                        ctx.waiting_continuation = true;
                        continuation_stream = stream_id;
                    }
                },
                .continuation => {
                    if (continuation_stream == null) return error.ProtocolError;
                    if (frame.header.stream_id != continuation_stream.?) return error.ProtocolError;

                    const idx = context_map.get(continuation_stream.?) orelse return error.ProtocolError;
                    var ctx = &contexts.items[idx];

                    if (ctx.pending_headers_block.items.len > self.config.max_header_size or
                        frame.payload.len > self.config.max_header_size - ctx.pending_headers_block.items.len)
                    {
                        return error.HeaderTooLarge;
                    }
                    try ctx.pending_headers_block.appendSlice(self.allocator, frame.payload);
                    if ((frame.header.flags & 0x04) != 0) {
                        const decoded = try hpack.decodeHeadersWithLimit(
                            &stream_manager.hpack_decoder,
                            ctx.pending_headers_block.items,
                            self.allocator,
                            local_settings.max_header_list_size,
                        );
                        defer {
                            for (decoded) |header| {
                                self.allocator.free(header.name);
                                self.allocator.free(header.value);
                            }
                            self.allocator.free(decoded);
                        }

                        if (ctx.pending_is_trailers) {
                            try validateRequestTrailers(@TypeOf(decoded[0]), decoded);
                        } else {
                            try self.parseHeaders(
                                @TypeOf(decoded[0]),
                                decoded,
                                &ctx.request_headers,
                                &ctx.method_raw,
                                &ctx.method_owned,
                                &ctx.path_raw,
                                &ctx.path_owned,
                                &ctx.scheme_raw,
                                &ctx.scheme_owned,
                                &ctx.authority_raw,
                                &ctx.authority_owned,
                            );
                            ctx.expected_content_length = try requestContentLength(&ctx.request_headers);
                            ctx.initial_headers_parsed = true;
                        }

                        ctx.pending_headers_block.clearRetainingCapacity();
                        ctx.waiting_continuation = false;
                        ctx.pending_is_trailers = false;
                        continuation_stream = null;
                        ctx.header_deadline = null;

                        if ((ctx.pending_headers_flags & 0x01) != 0) {
                            ctx.headers_complete = true;
                            stream_manager.getStream(ctx.stream_id).?.receiveEndStream();
                        }
                    }
                },
                .data => {
                    if (frame.header.stream_id == 0) return error.ProtocolError;
                    const idx = context_map.get(frame.header.stream_id) orelse return error.ProtocolError;
                    var ctx = &contexts.items[idx];
                    if (ctx.done) return error.StreamClosed;
                    const remote_stream = stream_manager.getStream(ctx.stream_id) orelse
                        return error.ProtocolError;
                    if (!remote_stream.canReceive()) return error.StreamClosed;
                    const flow_amount = std.math.cast(i32, frame.payload.len) orelse
                        return error.FlowControlError;
                    if (flow_amount > remote_stream.recv_window or
                        (!frame_from_queue and flow_amount > stream_manager.connection_recv_window))
                    {
                        return error.FlowControlError;
                    }
                    remote_stream.recv_window -= flow_amount;
                    if (!frame_from_queue) stream_manager.connection_recv_window -= flow_amount;

                    var data_slice = frame.payload;
                    if ((frame.header.flags & 0x08) != 0) {
                        if (frame.payload.len == 0) return error.ProtocolError;
                        const pad_len = frame.payload[0];
                        if (frame.payload.len < @as(usize, pad_len) + 1) return error.ProtocolError;
                        data_slice = frame.payload[1 .. frame.payload.len - pad_len];
                    }

                    if (ctx.request_body.items.len + data_slice.len > self.config.max_body_size) {
                        return error.RequestTooLarge;
                    }
                    const next_body_bytes = std.math.add(
                        u64,
                        ctx.received_body_bytes,
                        data_slice.len,
                    ) catch return error.RequestTooLarge;
                    if (ctx.expected_content_length) |expected| {
                        if (next_body_bytes > expected) return error.RequestBodyOverrun;
                    }
                    try ctx.request_body.appendSlice(self.allocator, data_slice);
                    ctx.received_body_bytes = next_body_bytes;

                    if (frame.payload.len > 0) {
                        const window_increment: u31 = @intCast(frame.payload.len);
                        const window_update = h2stream.buildWindowUpdatePayload(window_increment);
                        try conn.writeFrame(.{
                            .length = @intCast(window_update.len),
                            .frame_type = .window_update,
                            .flags = 0,
                            .stream_id = ctx.stream_id,
                        }, &window_update);
                        try conn.writeFrame(.{
                            .length = @intCast(window_update.len),
                            .frame_type = .window_update,
                            .flags = 0,
                            .stream_id = 0,
                        }, &window_update);
                        try remote_stream.updateRecvWindow(flow_amount);
                        try stream_manager.updateConnectionRecvWindow(flow_amount);
                    }

                    if ((frame.header.flags & 0x01) != 0) {
                        ctx.headers_complete = true;
                        remote_stream.receiveEndStream();
                    }
                },
                .rst_stream => {
                    if (frame.header.stream_id == 0 or frame.payload.len != 4) return error.ProtocolError;
                    if (context_map.get(frame.header.stream_id)) |idx| {
                        contexts.items[idx].done = true;
                        if (stream_manager.getStream(frame.header.stream_id)) |remote_stream| {
                            remote_stream.reset();
                        }
                    } else if (stream_manager.getStream(frame.header.stream_id)) |closed_stream| {
                        if (closed_stream.state != .closed) return error.ProtocolError;
                    } else if (isImplicitlyClosedClientStream(
                        frame.header.stream_id,
                        last_client_stream_id,
                    )) {
                        // Lower skipped odd IDs are implicitly closed.
                    } else {
                        return error.ProtocolError;
                    }
                },
                .goaway => {
                    return;
                },
                .push_promise => return error.ProtocolError,
                .window_update => {
                    if (frame.header.stream_id != 0 and
                        stream_manager.getStream(frame.header.stream_id) == null and
                        isImplicitlyClosedClientStream(
                            frame.header.stream_id,
                            last_client_stream_id,
                        ))
                    {
                        _ = try h2stream.parseWindowUpdatePayload(frame.payload);
                    } else {
                        try applyHTTP2SendWindowUpdate(
                            &stream_manager,
                            frame.header,
                            frame.payload,
                        );
                    }
                },
                .priority => {},
                _ => {},
            }

            // Process streams whose headers are complete (sequential processing).
            for (contexts.items) |*ctx| {
                if (ctx.done or !ctx.headers_complete) continue;

                if (!ctx.method_owned) return error.ProtocolError;
                try validateRequestBodyLength(ctx);
                const method = types.Method.fromString(ctx.method_raw) orelse .CUSTOM;
                const is_connect = method == .CONNECT;
                if (is_connect) {
                    if (ctx.authority_raw == null or ctx.authority_raw.?.len == 0 or
                        ctx.scheme_owned or ctx.path_owned)
                    {
                        return error.ProtocolError;
                    }
                } else {
                    if (!ctx.scheme_owned or !ctx.path_owned or ctx.path_raw.len == 0) {
                        return error.ProtocolError;
                    }
                    if (!std.ascii.eqlIgnoreCase(ctx.scheme_raw, "http") and
                        !std.ascii.eqlIgnoreCase(ctx.scheme_raw, "https"))
                    {
                        return error.ProtocolError;
                    }
                }

                const scheme = if (is_connect) default_scheme else ctx.scheme_raw;
                const path = if (is_connect) "/" else ctx.path_raw;
                const authority = ctx.authority_raw orelse
                    ctx.request_headers.get(HeaderName.HOST) orelse
                    return error.ProtocolError;
                if (authority.len == 0) return error.ProtocolError;
                if (ctx.request_headers.get(HeaderName.HOST) == null) {
                    try ctx.request_headers.append(HeaderName.HOST, authority);
                }

                const url = try std.fmt.allocPrint(self.allocator, "{s}://{s}{s}", .{ scheme, authority, path });
                defer self.allocator.free(url);

                var req = try Request.init(self.allocator, method, url);
                defer req.deinit();
                req.version = .HTTP_2;
                if (method == .CUSTOM) try req.setCustomMethod(ctx.method_raw);

                req.headers.deinit();
                req.headers = Headers.init(self.allocator);
                for (ctx.request_headers.entries.items) |entry| {
                    try req.headers.append(entry.name, entry.value);
                }

                if (ctx.request_body.items.len > 0) {
                    req.body = try self.allocator.dupe(u8, ctx.request_body.items);
                    req.body_owned = true;
                }

                var response = self.executeServerRequest(&req, null, null) catch {
                    var internal = Response.init(self.allocator, status_mod.StatusCode.INTERNAL_SERVER_ERROR);
                    defer internal.deinit();
                    internal.version = .HTTP_2;
                    self.sendHTTP2Response(
                        conn,
                        &stream_manager,
                        ctx.stream_id,
                        &internal,
                        frame_context,
                        &pending_frames,
                        &pending_frame_bytes,
                        &queued_continuation_stream,
                        last_client_stream_id,
                    ) catch |err| switch (err) {
                        error.StreamReset => {
                            ctx.done = true;
                            last_processed_stream_id = @max(last_processed_stream_id, ctx.stream_id);
                            processed_this_iteration = true;
                            continue;
                        },
                        else => return err,
                    };
                    ctx.done = true;
                    last_processed_stream_id = @max(last_processed_stream_id, ctx.stream_id);
                    processed_this_iteration = true;
                    continue;
                };
                defer response.deinit();
                response.version = .HTTP_2;

                self.sendHTTP2Response(
                    conn,
                    &stream_manager,
                    ctx.stream_id,
                    &response,
                    frame_context,
                    &pending_frames,
                    &pending_frame_bytes,
                    &queued_continuation_stream,
                    last_client_stream_id,
                ) catch |err| switch (err) {
                    error.StreamReset => {
                        ctx.done = true;
                        last_processed_stream_id = @max(last_processed_stream_id, ctx.stream_id);
                        processed_this_iteration = true;
                        continue;
                    },
                    else => return err,
                };
                ctx.done = true;
                last_processed_stream_id = @max(last_processed_stream_id, ctx.stream_id);
                processed_this_iteration = true;
            }

            var context_index: usize = 0;
            while (context_index < contexts.items.len) {
                if (!contexts.items[context_index].done) {
                    context_index += 1;
                    continue;
                }
                const completed_stream_id = contexts.items[context_index].stream_id;
                contexts.items[context_index].deinit(self.allocator);
                _ = contexts.orderedRemove(context_index);
                _ = context_map.remove(completed_stream_id);
                if (stream_manager.getStream(completed_stream_id)) |completed_stream| {
                    if (completed_stream.state != .closed) completed_stream.reset();
                }
                try closed_stream_order.append(self.allocator, completed_stream_id);
                if (closed_stream_order.items.len > 1024) {
                    const expired_stream = closed_stream_order.orderedRemove(0);
                    stream_manager.removeStream(expired_stream);
                }
                var shifted = context_index;
                while (shifted < contexts.items.len) : (shifted += 1) {
                    try context_map.put(contexts.items[shifted].stream_id, shifted);
                }
            }

            // Check if all streams are done.
            all_done = true;
            for (contexts.items) |*ctx| {
                if (!ctx.done) {
                    all_done = false;
                    break;
                }
            }
            // If no streams exist yet and none are pending, keep looping for new streams.
            if (contexts.items.len == 0) {
                all_done = false;
            }
            // If we just processed a response, continue reading to catch any new streams
            // that may already be in the socket buffer.
            if (processed_this_iteration) {
                all_done = false;
            }
        }

        // Determine last stream ID for GOAWAY.
        const last_stream_id = last_processed_stream_id;

        const goaway_frame = try h2stream.buildGoawayFrame(last_stream_id, .no_error, null, self.allocator);
        defer self.allocator.free(goaway_frame);
        try conn.writer.writeAll(goaway_frame);
    }

    /// Sends an error response over a TLS connection.
    fn sendTLSError(self: *Self, tls_conn: *tls_mod.Connection, code: u16) !void {
        var resp = Response.init(self.allocator, code);
        defer resp.deinit();

        try self.ensureContentLengthHeader(&resp);

        const formatted = try http.formatResponse(&resp, self.allocator);
        defer self.allocator.free(formatted);

        tls_conn.writeAll(formatted) catch |e| {
            self.log(.err, "TLS write failed: {}\n", .{e});
            return;
        };
    }

    fn sendHTTP2Response(
        self: *Self,
        conn: *http.HTTP2Connection,
        stream_manager: *h2stream.StreamManager,
        stream_id: u31,
        response: *Response,
        frame_context: *IoContext,
        pending_frames: *std.ArrayList(http.HTTP2Connection.Frame),
        pending_frame_bytes: *usize,
        queued_continuation_stream: *?u31,
        last_client_stream_id: u31,
    ) !void {
        try self.ensureContentLengthHeader(response);
        const response_stream = stream_manager.getStream(stream_id) orelse
            return error.InvalidStreamState;
        if (!response_stream.canSend()) return error.InvalidStreamState;

        var response_headers = std.ArrayList(hpack.HeaderEntry).empty;
        defer response_headers.deinit(self.allocator);

        var owned_header_names = std.ArrayList([]u8).empty;
        defer {
            for (owned_header_names.items) |name| {
                self.allocator.free(name);
            }
            owned_header_names.deinit(self.allocator);
        }

        var status_buf: [8]u8 = undefined;
        const status_str = try std.fmt.bufPrint(&status_buf, "{d}", .{response.status.code});
        try response_headers.append(self.allocator, .{ .name = ":status", .value = status_str });

        for (response.headers.entries.items) |entry| {
            if (common.isConnectionSpecificHeader(entry.name)) continue;
            if (entry.name.len > 0 and entry.name[0] == ':') continue;

            const lowered = try common.dupLowerAscii(self.allocator, entry.name);
            try owned_header_names.append(self.allocator, lowered);
            try response_headers.append(self.allocator, .{ .name = lowered, .value = entry.value });
        }

        const has_body = response.body != null and response.body.?.len > 0;
        const max_frame_size: u32 = @max(conn.peer_settings.max_frame_size, 16 * 1024);

        const headers_frames = try h2stream.buildHeadersAndContinuations(
            stream_manager,
            stream_id,
            response_headers.items,
            null,
            max_frame_size,
            !has_body,
            self.allocator,
        );
        defer self.allocator.free(headers_frames);

        try conn.writer.writeAll(headers_frames);

        if (!has_body) {
            response_stream.sendEndStream();
            return;
        }

        const body = response.body.?;
        const data_max_frame_size: usize = @intCast(max_frame_size);
        const send_wait_deadline = if (self.config.write_timeout_ms > 0)
            Deadline.afterMs(self.config.write_timeout_ms)
        else
            null;
        var offset: usize = 0;
        while (offset < body.len) {
            while (response_stream.send_window <= 0 or
                stream_manager.connection_send_window <= 0)
            {
                try self.pumpHTTP2SendWindow(
                    conn,
                    stream_manager,
                    stream_id,
                    frame_context,
                    send_wait_deadline,
                    pending_frames,
                    pending_frame_bytes,
                    queued_continuation_stream,
                    last_client_stream_id,
                );
                if (!response_stream.canSend()) return error.StreamReset;
            }
            const stream_window: usize = @intCast(response_stream.send_window);
            const connection_window: usize = @intCast(stream_manager.connection_send_window);
            const chunk_len = @min(
                body.len - offset,
                data_max_frame_size,
                stream_window,
                connection_window,
            );
            if (chunk_len == 0) continue;
            const is_last = offset + chunk_len == body.len;
            try conn.writeFrame(.{
                .length = @intCast(chunk_len),
                .frame_type = .data,
                .flags = if (is_last) 0x01 else 0,
                .stream_id = stream_id,
            }, body[offset .. offset + chunk_len]);
            const debit: i32 = @intCast(chunk_len);
            try response_stream.updateSendWindow(-debit);
            try stream_manager.updateConnectionSendWindow(-debit);
            offset += chunk_len;
            if (is_last) response_stream.sendEndStream();
        }
    }

    /// Sends HTTP/2 trailers for a stream.
    /// Trailers are sent as a HEADERS frame with END_STREAM flag set.
    pub fn sendHTTP2Trailers(
        self: *Self,
        conn: *http.HTTP2Connection,
        stream_manager: *h2stream.StreamManager,
        stream_id: u31,
        trailer_headers: *const Headers,
    ) !void {
        var hpack_entries = std.ArrayList(hpack.HeaderEntry).empty;
        defer hpack_entries.deinit(self.allocator);

        var owned_names = std.ArrayList([]u8).empty;
        defer {
            for (owned_names.items) |name| {
                self.allocator.free(name);
            }
            owned_names.deinit(self.allocator);
        }

        for (trailer_headers.entries.items) |entry| {
            if (common.isConnectionSpecificHeader(entry.name)) continue;
            if (entry.name.len > 0 and entry.name[0] == ':') continue;

            const lowered = try common.dupLowerAscii(self.allocator, entry.name);
            try owned_names.append(self.allocator, lowered);
            try hpack_entries.append(self.allocator, .{ .name = lowered, .value = entry.value });
        }

        const max_frame_size: u32 = @max(conn.peer_settings.max_frame_size, 16 * 1024);

        const headers_frames = try h2stream.buildHeadersAndContinuations(
            stream_manager,
            stream_id,
            hpack_entries.items,
            null,
            max_frame_size,
            true, // END_STREAM
            self.allocator,
        );
        defer self.allocator.free(headers_frames);

        try conn.writer.writeAll(headers_frames);
    }

    /// Server push is intentionally disabled. The method remains for source
    /// compatibility and always returns `error.PushDisabled`.
    pub fn pushPromise(
        _: *Self,
        _: *http.HTTP2Connection,
        _: *h2stream.StreamManager,
        _: u31,
        _: types.Method,
        _: []const u8,
        _: ?[]const hpack.HeaderEntry,
    ) !u31 {
        return error.PushDisabled;
    }

    fn handleHTTP3Transaction(self: *Self, peer_addr: net.Address, first_datagram: []const u8) !void {
        var control_stream_payload = std.ArrayList(u8).empty;
        defer control_stream_payload.deinit(self.allocator);

        var request_stream_payload = std.ArrayList(u8).empty;
        defer request_stream_payload.deinit(self.allocator);

        var request_stream_id: ?u64 = null;
        var request_done = false;
        var client_cid: ?quic.ConnectionId = null;

        // HTTP/3 flow control state
        var conn_max_data: u64 = 10 * 1024 * 1024; // 10 MB default
        var stream_max_data: u64 = 1024 * 1024; // 1 MB default per stream

        var recv_buf: [64 * 1024]u8 = undefined;
        var packet_data: []const u8 = first_datagram;

        while (true) {
            const decoded = try decodeHTTP3IncomingDatagram(packet_data);
            if (decoded.client_scid) |cid| {
                client_cid = cid;
            }

            if (decoded.stream_id == 2) {
                try control_stream_payload.appendSlice(self.allocator, decoded.data);
            } else if ((decoded.stream_id & 0x03) == 0) {
                request_stream_id = decoded.stream_id;
                try request_stream_payload.appendSlice(self.allocator, decoded.data);
                if (decoded.fin) {
                    request_done = true;
                }
            }

            if (request_done) break;

            const incoming = self.udp_socket.?.recvFrom(&recv_buf) catch return error.ProtocolError;
            packet_data = recv_buf[0..incoming.n];
        }

        if (control_stream_payload.items.len > 0) {
            // Parse control stream frames, extracting flow control values
            var cs_offset: usize = 0;
            // Skip stream type byte
            if (control_stream_payload.items.len > 0) {
                const st = try http.decodeVarInt(control_stream_payload.items);
                cs_offset = st.len;
            }
            var saw_settings = false;
            while (cs_offset < control_stream_payload.items.len) {
                const frame = try http.HTTP3FrameHeader.decode(control_stream_payload.items[cs_offset..]);
                cs_offset += frame.len;
                const plen: usize = @intCast(frame.header.length);
                if (control_stream_payload.items.len < cs_offset + plen) break;
                const payload = control_stream_payload.items[cs_offset .. cs_offset + plen];
                cs_offset += plen;

                if (frame.header.frame_type == @intFromEnum(http.HTTP3FrameType.settings)) {
                    _ = try http.parseHTTP3SettingsPayload(payload);
                    saw_settings = true;
                } else if (frame.header.frame_type == @intFromEnum(http.HTTP3FrameType.max_data)) {
                    if (payload.len > 0) {
                        const val = try http.decodeVarInt(payload);
                        conn_max_data = val.value;
                    }
                } else if (frame.header.frame_type == @intFromEnum(http.HTTP3FrameType.max_stream_data)) {
                    if (payload.len > 0) {
                        const sid = try http.decodeVarInt(payload);
                        const data_limit = try http.decodeVarInt(payload[sid.len..]);
                        stream_max_data = data_limit.value;
                    }
                }
            }
        }

        const stream_id = request_stream_id orelse return error.ProtocolError;
        const dst_cid = client_cid orelse return error.ProtocolError;

        var request_headers = Headers.init(self.allocator);
        defer request_headers.deinit();

        var request_body = std.ArrayList(u8).empty;
        defer request_body.deinit(self.allocator);

        var method_raw: []const u8 = "GET";
        var method_owned = false;
        defer if (method_owned) self.allocator.free(method_raw);

        var path_raw: []const u8 = "/";
        var path_owned = false;
        defer if (path_owned) self.allocator.free(path_raw);

        var scheme_raw: []const u8 = "http";
        var scheme_owned = false;
        defer if (scheme_owned) self.allocator.free(scheme_raw);

        var authority_raw: ?[]const u8 = null;
        var authority_owned = false;
        defer if (authority_owned and authority_raw != null) self.allocator.free(authority_raw.?);

        var qpack_ctx = qpack.QPACKContext.initWithCapacity(
            self.allocator,
            common.clampU64ToUsize(self.config.http3_settings.qpack_max_table_capacity),
        );
        defer qpack_ctx.deinit();

        var offset: usize = 0;
        while (offset < request_stream_payload.items.len) {
            const frame = try http.HTTP3FrameHeader.decode(request_stream_payload.items[offset..]);
            offset += frame.len;

            const payload_len: usize = @intCast(frame.header.length);
            if (request_stream_payload.items.len < offset + payload_len) return error.ProtocolError;

            const frame_payload = request_stream_payload.items[offset .. offset + payload_len];
            offset += payload_len;

            if (frame.header.frame_type == @intFromEnum(http.HTTP3FrameType.headers)) {
                const decoded_headers = try qpack.decodeHeaders(&qpack_ctx, frame_payload, self.allocator);
                defer {
                    for (decoded_headers) |header| {
                        self.allocator.free(header.name);
                        self.allocator.free(header.value);
                    }
                    self.allocator.free(decoded_headers);
                }

                try self.parseHeaders(
                    @TypeOf(decoded_headers[0]),
                    decoded_headers,
                    &request_headers,
                    &method_raw,
                    &method_owned,
                    &path_raw,
                    &path_owned,
                    &scheme_raw,
                    &scheme_owned,
                    &authority_raw,
                    &authority_owned,
                );
            } else if (frame.header.frame_type == @intFromEnum(http.HTTP3FrameType.data)) {
                if (request_body.items.len + frame_payload.len > self.config.max_body_size) {
                    return error.RequestTooLarge;
                }
                try request_body.appendSlice(self.allocator, frame_payload);
            }
        }

        const scheme = if (scheme_raw.len == 0) "http" else scheme_raw;
        const path = if (path_raw.len == 0) "/" else path_raw;
        const authority = authority_raw orelse request_headers.get(HeaderName.HOST) orelse self.config.host;
        if (request_headers.get(HeaderName.HOST) == null) {
            try request_headers.append(HeaderName.HOST, authority);
        }

        const method = types.Method.fromString(method_raw) orelse .GET;

        const url = try std.fmt.allocPrint(self.allocator, "{s}://{s}{s}", .{ scheme, authority, path });
        defer self.allocator.free(url);

        var req = try Request.init(self.allocator, method, url);
        defer req.deinit();
        req.version = .HTTP_3;

        req.headers.deinit();
        req.headers = Headers.init(self.allocator);
        for (request_headers.entries.items) |entry| {
            try req.headers.append(entry.name, entry.value);
        }

        if (request_body.items.len > 0) {
            req.body = try self.allocator.dupe(u8, request_body.items);
            req.body_owned = true;
        }

        var response = self.executeServerRequest(&req, null, null) catch {
            // Send CONNECTION_CLOSE (application) on unrecoverable handler error
            self.sendHTTP3ConnectionCloseApp(peer_addr, dst_cid, @intFromEnum(http.HTTP3ErrorCode.internal_error), "handler error") catch {};
            var internal = Response.init(self.allocator, status_mod.StatusCode.INTERNAL_SERVER_ERROR);
            defer internal.deinit();
            internal.version = .HTTP_3;
            try self.sendHTTP3Response(peer_addr, dst_cid, stream_id, &internal, conn_max_data, stream_max_data);
            return;
        };
        defer response.deinit();
        response.version = .HTTP_3;

        try self.sendHTTP3Response(peer_addr, dst_cid, stream_id, &response, conn_max_data, stream_max_data);
    }

    fn sendHTTP3Response(
        self: *Self,
        peer_addr: net.Address,
        dst_cid: quic.ConnectionId,
        request_stream_id: u64,
        response: *Response,
        conn_max_data: u64,
        stream_max_data: u64,
    ) !void {
        try self.ensureContentLengthHeader(response);

        var qpack_ctx = qpack.QPACKContext.initWithCapacity(
            self.allocator,
            common.clampU64ToUsize(self.config.http3_settings.qpack_max_table_capacity),
        );
        defer qpack_ctx.deinit();

        var response_headers = std.ArrayList(qpack.HeaderEntry).empty;
        defer response_headers.deinit(self.allocator);

        var owned_header_names = std.ArrayList([]u8).empty;
        defer {
            for (owned_header_names.items) |name| {
                self.allocator.free(name);
            }
            owned_header_names.deinit(self.allocator);
        }

        var status_buf: [8]u8 = undefined;
        const status_str = try std.fmt.bufPrint(&status_buf, "{d}", .{response.status.code});
        try response_headers.append(self.allocator, .{ .name = ":status", .value = status_str });

        for (response.headers.entries.items) |entry| {
            if (common.isConnectionSpecificHeader(entry.name)) continue;
            if (entry.name.len > 0 and entry.name[0] == ':') continue;

            const lowered = try common.dupLowerAscii(self.allocator, entry.name);
            try owned_header_names.append(self.allocator, lowered);
            try response_headers.append(self.allocator, .{ .name = lowered, .value = entry.value });
        }

        const encoded_headers = try qpack.encodeHeaders(&qpack_ctx, response_headers.items, self.allocator);
        defer self.allocator.free(encoded_headers);

        var response_stream_payload = std.ArrayList(u8).empty;
        defer response_stream_payload.deinit(self.allocator);
        try http.appendHTTP3Frame(&response_stream_payload, self.allocator, .headers, encoded_headers);
        if (response.body) |body| {
            try http.appendHTTP3Frame(&response_stream_payload, self.allocator, .data, body);
        }

        var settings_payload = std.ArrayList(u8).empty;
        defer settings_payload.deinit(self.allocator);
        try http.encodeHTTP3SettingsPayload(self.config.http3_settings, self.allocator, &settings_payload);

        var control_stream_payload = std.ArrayList(u8).empty;
        defer control_stream_payload.deinit(self.allocator);
        try http.appendVarInt(&control_stream_payload, self.allocator, @intFromEnum(quic.HTTP3StreamType.control));
        try http.appendHTTP3Frame(&control_stream_payload, self.allocator, .settings, settings_payload.items);

        // Send MAX_DATA and MAX_STREAM_DATA to advertise our flow control limits
        {
            var max_data_payload = std.ArrayList(u8).empty;
            defer max_data_payload.deinit(self.allocator);
            try http.appendVarInt(&max_data_payload, self.allocator, conn_max_data);
            try http.appendHTTP3Frame(&control_stream_payload, self.allocator, .max_data, max_data_payload.items);
        }
        {
            var max_stream_data_payload = std.ArrayList(u8).empty;
            defer max_stream_data_payload.deinit(self.allocator);
            try http.appendVarInt(&max_stream_data_payload, self.allocator, request_stream_id);
            try http.appendVarInt(&max_stream_data_payload, self.allocator, stream_max_data);
            try http.appendHTTP3Frame(&control_stream_payload, self.allocator, .max_stream_data, max_stream_data_payload.items);
        }

        const server_cid = quic.ConnectionId.random();

        const control_packet = try buildHTTP3Datagram(
            self.allocator,
            dst_cid,
            server_cid,
            1,
            3,
            0,
            false,
            control_stream_payload.items,
        );
        defer self.allocator.free(control_packet);

        const response_packet = try buildHTTP3Datagram(
            self.allocator,
            dst_cid,
            server_cid,
            2,
            request_stream_id,
            0,
            true,
            response_stream_payload.items,
        );
        defer self.allocator.free(response_packet);

        const udp = if (self.udp_socket) |*u| u else return error.ProtocolError;
        _ = try udp.sendTo(peer_addr, control_packet);
        _ = try udp.sendTo(peer_addr, response_packet);
    }

    /// Sends an HTTP/3 GOAWAY frame on the control stream.
    pub fn sendHTTP3Goaway(
        self: *Self,
        peer_addr: net.Address,
        dst_cid: quic.ConnectionId,
        stream_id: u64,
    ) !void {
        var goaway_payload = std.ArrayList(u8).empty;
        defer goaway_payload.deinit(self.allocator);
        try http.appendVarInt(&goaway_payload, self.allocator, stream_id);

        var control_stream_payload = std.ArrayList(u8).empty;
        defer control_stream_payload.deinit(self.allocator);
        try http.appendVarInt(&control_stream_payload, self.allocator, @intFromEnum(quic.HTTP3StreamType.control));
        try http.appendHTTP3Frame(&control_stream_payload, self.allocator, .goaway, goaway_payload.items);

        const server_cid = quic.ConnectionId.random();
        const packet = try buildHTTP3Datagram(
            self.allocator,
            dst_cid,
            server_cid,
            1,
            3,
            0,
            false,
            control_stream_payload.items,
        );
        defer self.allocator.free(packet);

        const udp = if (self.udp_socket) |*u| u else return error.ProtocolError;
        _ = try udp.sendTo(peer_addr, packet);
    }

    /// Sends a QUIC CONNECTION_CLOSE (application, type 0x1d) frame.
    pub fn sendHTTP3ConnectionCloseApp(
        self: *Self,
        peer_addr: net.Address,
        dst_cid: quic.ConnectionId,
        error_code: u64,
        reason: []const u8,
    ) !void {
        var close_buf: [128]u8 = undefined;
        const frame = quic.ConnectionCloseFrame{
            .error_code = error_code,
            .reason_phrase = reason,
        };
        const frame_len = try frame.encode(true, &close_buf);

        var packet = try buildQuicInitialPacket(self.allocator, dst_cid, quic.ConnectionId.random(), 0, close_buf[0..frame_len]);
        defer packet.deinit(self.allocator);

        const udp = if (self.udp_socket) |*u| u else return error.ProtocolError;
        _ = try udp.sendTo(peer_addr, packet.items);
    }

    /// Sends a QUIC RESET_STREAM frame to cancel a stream.
    pub fn sendHTTP3ResetStream(
        self: *Self,
        peer_addr: net.Address,
        dst_cid: quic.ConnectionId,
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    ) !void {
        var frame_buf: [64]u8 = undefined;
        const frame = quic.ResetStreamFrame{
            .stream_id = stream_id,
            .error_code = error_code,
            .final_size = final_size,
        };
        const frame_len = try frame.encode(&frame_buf);

        var packet = try buildQuicInitialPacket(self.allocator, dst_cid, quic.ConnectionId.random(), 0, frame_buf[0..frame_len]);
        defer packet.deinit(self.allocator);

        const udp = if (self.udp_socket) |*u| u else return error.ProtocolError;
        _ = try udp.sendTo(peer_addr, packet.items);
    }

    /// Sends a QUIC STOP_SENDING frame to tell the peer to stop sending on a stream.
    pub fn sendHTTP3StopSending(
        self: *Self,
        peer_addr: net.Address,
        dst_cid: quic.ConnectionId,
        stream_id: u64,
        error_code: u64,
    ) !void {
        var frame_buf: [64]u8 = undefined;
        const frame = quic.StopSendingFrame{
            .stream_id = stream_id,
            .error_code = error_code,
        };
        const frame_len = try frame.encode(&frame_buf);

        var packet = try buildQuicInitialPacket(self.allocator, dst_cid, quic.ConnectionId.random(), 0, frame_buf[0..frame_len]);
        defer packet.deinit(self.allocator);

        const udp = if (self.udp_socket) |*u| u else return error.ProtocolError;
        _ = try udp.sendTo(peer_addr, packet.items);
    }

    /// Sends a QUIC CONNECTION_CLOSE (transport, type 0x1c) frame.
    pub fn sendHTTP3ConnectionCloseTransport(
        self: *Self,
        peer_addr: net.Address,
        dst_cid: quic.ConnectionId,
        error_code: u64,
        frame_type: u64,
        reason: []const u8,
    ) !void {
        var close_buf: [128]u8 = undefined;
        const frame = quic.ConnectionCloseFrame{
            .error_code = error_code,
            .frame_type = frame_type,
            .reason_phrase = reason,
        };
        const frame_len = try frame.encode(false, &close_buf);

        var packet = try buildQuicInitialPacket(self.allocator, dst_cid, quic.ConnectionId.random(), 0, close_buf[0..frame_len]);
        defer packet.deinit(self.allocator);

        const udp = if (self.udp_socket) |*u| u else return error.ProtocolError;
        _ = try udp.sendTo(peer_addr, packet.items);
    }

    fn executeServerRequest(self: *Self, req: *Request, sock: ?*Socket, tls_conn: ?*tls_mod.Connection) !Response {
        if (self.config.metrics) |m| {
            m.recordRequest();
            m.serverRequestStarted();
        }
        const start_time_ms: u64 = @intCast(@max(common.nowMillis(), 0));
        var ctx = Context.init(self.allocator, req);
        ctx.server = self;

        // Store stream writer in context so handlers can stream responses.
        if (sock) |s| {
            var writer = StreamWriter.fromSocket(self.allocator, s);
            try ctx.data.put("__stream_writer", @ptrCast(&writer));
        } else if (tls_conn) |c| {
            var writer = StreamWriter.fromTLS(self.allocator, c);
            try ctx.data.put("__stream_writer", @ptrCast(&writer));
        }

        defer ctx.deinit();

        for (self.pre_route_hooks.items) |hook| {
            try hook(&ctx);
        }

        var suppress_body = false;
        const find_result = self.router.findEx(req.method, req.uri.path);

        var route_handler: ?Handler = null;
        var allowed_methods_for_405: ?[]const types.Method = null;

        switch (find_result) {
            .found => |m| {
                defer self.allocator.free(m.params);
                for (m.params) |p| {
                    try ctx.params.put(p.name, p.value);
                }
                route_handler = m.handler;
            },
            .method_not_allowed => |allowed| {
                allowed_methods_for_405 = allowed;
            },
            .not_found => {
                // If HEAD is not explicitly registered, fall back to GET semantics
                // and suppress the response body.
                if (req.method == .HEAD) {
                    if (self.router.find(.GET, req.uri.path)) |m| {
                        defer self.allocator.free(m.params);
                        for (m.params) |p| {
                            try ctx.params.put(p.name, p.value);
                        }
                        route_handler = m.handler;
                        suppress_body = true;
                    }
                }
            },
        }

        // Handle trailing slash redirect (301) when policy is .redirect.
        if (self.router.redirect_trailing_slash and route_handler != null) {
            const path = req.uri.path;
            if (path.len > 1) {
                var redirect_path = std.ArrayList(u8).empty;
                defer redirect_path.deinit(self.allocator);
                try redirect_path.appendSlice(self.allocator, path[0 .. path.len - 1]);
                var response = Response.init(self.allocator, status_mod.StatusCode.MOVED_PERMANENTLY);
                response.headers.append("Location", redirect_path.items) catch {};
                return response;
            }
        }

        const FallbackHandler = struct {
            server: *Self,
            route_handler: ?Handler,
            suppress_body: bool,
            allowed_methods: ?[]const types.Method,

            fn handle(c: *Context) anyerror!Response {
                const self_ptr = @This();
                const s = c.data.get("__fallback_state") orelse return error.MissingFallbackState;
                const state: *const self_ptr = @ptrCast(@alignCast(s));

                if (state.route_handler) |handler| {
                    return handler(c);
                }

                // Use the pre-computed allowed methods from findEx if available.
                if (state.allowed_methods) |allowed| {
                    defer state.server.allocator.free(allowed);
                    if (c.request.method == .OPTIONS) {
                        var response = Response.init(state.server.allocator, status_mod.StatusCode.NO_CONTENT);
                        try state.server.setAllowHeader(&response.headers, allowed);
                        return response;
                    } else {
                        var response = Response.init(state.server.allocator, status_mod.StatusCode.METHOD_NOT_ALLOWED);
                        try state.server.setAllowHeader(&response.headers, allowed);
                        return response;
                    }
                }

                // Fall back to allowedMethods scan for HEAD->GET fallback.
                var allow_methods: [16]types.Method = undefined;
                const allow_count = state.server.router.allowedMethods(c.request.uri.path, &allow_methods);

                if (c.request.method == .OPTIONS and allow_count > 0) {
                    var response = Response.init(state.server.allocator, status_mod.StatusCode.NO_CONTENT);
                    try state.server.setAllowHeader(&response.headers, allow_methods[0..allow_count]);
                    return response;
                } else if (allow_count > 0) {
                    var response = Response.init(state.server.allocator, status_mod.StatusCode.METHOD_NOT_ALLOWED);
                    try state.server.setAllowHeader(&response.headers, allow_methods[0..allow_count]);
                    return response;
                } else if (state.server.global_handler) |global_handler| {
                    return global_handler(c);
                } else {
                    return Response.init(state.server.allocator, status_mod.StatusCode.NOT_FOUND);
                }
            }
        };

        var fallback = FallbackHandler{
            .server = self,
            .route_handler = route_handler,
            .suppress_body = suppress_body,
            .allowed_methods = allowed_methods_for_405,
        };
        try ctx.data.put("__fallback_state", @ptrCast(&fallback));
        defer _ = ctx.data.remove("__fallback_state");

        var response = self.executeMiddleware(&ctx, FallbackHandler.handle) catch |err| {
            if (self.config.on_error) |on_err| on_err(err, &ctx);
            return err;
        };

        if (suppress_body or req.method == .HEAD) {
            if (response.body_owned) {
                if (response.body) |body| self.allocator.free(body);
                response.body_owned = false;
            }
            response.body = null;
        }

        // Transfer streaming flag from context to response so server can skip formatting.
        response.streaming_done = ctx.streaming_done;

        // Record metrics.
        if (self.config.metrics) |m| {
            const now_ms: u64 = @intCast(@max(common.nowMillis(), 0));
            const elapsed_ms: u64 = now_ms -| start_time_ms;
            const latency_ns = elapsed_ms * 1_000_000;
            const body_len: u64 = if (response.body) |b| @intCast(b.len) else 0;
            m.recordResponse(response.status.code, body_len, latency_ns);
            const is_server_error = response.status.code >= 500;
            m.serverRequestCompleted(is_server_error);
        }

        return response;
    }

    /// Sends an error response.
    fn sendError(self: *Self, socket: *Socket, code: u16) !void {
        var resp = Response.init(self.allocator, code);
        defer resp.deinit();

        try self.ensureContentLengthHeader(&resp);

        const formatted = try http.formatResponse(&resp, self.allocator);
        defer self.allocator.free(formatted);

        try socket.sendAll(formatted);
    }

    fn ensureContentLengthHeader(self: *Self, response: *Response) !void {
        _ = self;
        if (response.headers.get(HeaderName.CONTENT_LENGTH) != null) return;
        if (response.headers.isChunked()) return;
        if ((response.status.code >= 100 and response.status.code < 200) or
            response.status.code == status_mod.StatusCode.NO_CONTENT or
            response.status.code == status_mod.StatusCode.NOT_MODIFIED)
        {
            return;
        }

        const body_len: usize = if (response.body) |b| b.len else 0;
        var len_buf: [32]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{body_len}) catch unreachable;
        try response.headers.set(HeaderName.CONTENT_LENGTH, len_str);
    }

    /// Sets the `Allow` header for automatic OPTIONS and 405 responses.
    fn setAllowHeader(self: *Self, headers: *Headers, methods: []const types.Method) !void {
        var allow = std.ArrayList(u8).empty;
        defer allow.deinit(self.allocator);
        const writer = list_writer.init(self.allocator, &allow);

        var first = true;
        var has_options = false;

        for (methods) |m| {
            if (m == .OPTIONS) has_options = true;
            if (!first) try writer.writeAll(", ");
            first = false;
            try writer.writeAll(m.toString());
        }

        if (!has_options) {
            if (!first) try writer.writeAll(", ");
            try writer.writeAll("OPTIONS");
        }

        try headers.set("Allow", allow.items);
    }

    const MiddlewareExecState = struct {
        server: *Self,
        route_handler: Handler,
        index: usize = 0,
    };

    fn executeMiddleware(self: *Self, ctx: *Context, route_handler: Handler) !Response {
        var state = MiddlewareExecState{
            .server = self,
            .route_handler = route_handler,
        };
        try ctx.data.put("__mw_exec_state", @ptrCast(&state));
        defer _ = ctx.data.remove("__mw_exec_state");

        return middlewareNext(ctx);
    }

    fn middlewareNext(ctx: *Context) anyerror!Response {
        const raw = ctx.data.get("__mw_exec_state") orelse return error.MissingMiddlewareState;
        const state: *MiddlewareExecState = @ptrCast(@alignCast(raw));

        if (state.index < state.server.middleware.items.len) {
            const mw = state.server.middleware.items[state.index];
            state.index += 1;
            return mw.handler(ctx, middlewareNext);
        }

        return state.route_handler(ctx);
    }
};

const HTTP3IncomingDatagram = struct {
    stream_id: u64,
    fin: bool,
    data: []const u8,
    client_scid: ?quic.ConnectionId = null,
};

fn decodeHTTP3IncomingDatagram(datagram: []const u8) !HTTP3IncomingDatagram {
    if (datagram.len == 0) return error.ProtocolError;

    var offset: usize = 0;
    var client_scid: ?quic.ConnectionId = null;

    if ((datagram[0] & 0x80) != 0) {
        const long_header = try quic.LongHeader.decode(datagram);
        offset = long_header.len;
        if (long_header.header.scid.len > 0) {
            client_scid = long_header.header.scid;
        }
    } else {
        const short_header = try quic.ShortHeader.decode(datagram, 8);
        offset = short_header.len;
    }

    const packet_number = try quic.decodeVarInt(datagram[offset..]);
    _ = packet_number.value;
    offset += packet_number.len;

    if (offset >= datagram.len) return error.ProtocolError;
    if (!quic.FrameType.isStream(@as(u64, datagram[offset]))) return error.ProtocolError;

    const stream = try quic.StreamFrame.decode(datagram[offset..]);
    if (stream.len != datagram[offset..].len) return error.ProtocolError;

    return .{
        .stream_id = stream.frame.stream_id,
        .fin = stream.frame.fin,
        .data = stream.frame.data,
        .client_scid = client_scid,
    };
}

fn buildQuicInitialPacket(
    allocator: Allocator,
    dst_cid: quic.ConnectionId,
    scid: quic.ConnectionId,
    packet_number: u64,
    frame_payload: []const u8,
) !std.ArrayList(u8) {
    var packet = std.ArrayList(u8).empty;
    errdefer packet.deinit(allocator);

    var header_buf: [128]u8 = undefined;
    const header_len = try (quic.LongHeader{
        .packet_type = .initial,
        .version = .v1,
        .dcid = dst_cid,
        .scid = scid,
    }).encode(&header_buf);
    try packet.appendSlice(allocator, header_buf[0..header_len]);

    var pn_buf: [8]u8 = undefined;
    const pn_len = try quic.encodeVarInt(packet_number, &pn_buf);
    try packet.appendSlice(allocator, pn_buf[0..pn_len]);
    try packet.appendSlice(allocator, frame_payload);

    return packet;
}

fn buildHTTP3Datagram(
    allocator: Allocator,
    dcid: quic.ConnectionId,
    scid: quic.ConnectionId,
    packet_number: u64,
    stream_id: u64,
    stream_offset: u64,
    fin: bool,
    payload: []const u8,
) ![]u8 {
    const frame_storage = try allocator.alloc(u8, payload.len + 64);
    defer allocator.free(frame_storage);

    const stream_frame = quic.StreamFrame{
        .stream_id = stream_id,
        .offset = stream_offset,
        .length = @intCast(payload.len),
        .fin = fin,
        .data = payload,
    };
    const frame_len = try stream_frame.encode(frame_storage);

    var packet = try buildQuicInitialPacket(allocator, dcid, scid, packet_number, frame_storage[0..frame_len]);
    defer packet.deinit(allocator);
    return packet.toOwnedSlice(allocator);
}

fn trailerHeaderNames(allocator: Allocator, headers: *const Headers) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    const writer = list_writer.init(allocator, &out);

    var first = true;
    for (headers.entries.items) |h| {
        if (!first) try writer.writeAll(", ");
        first = false;
        try writer.writeAll(h.name);
    }

    return out.toOwnedSlice(allocator);
}

fn buildStaticEtag(allocator: Allocator, path: []const u8, stat: anytype) ![]u8 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(path);

    const size_u64: u64 = @intCast(stat.size);
    hasher.update(mem.asBytes(&size_u64));

    const Stat = @TypeOf(stat);
    if (@hasField(Stat, "mtime")) {
        const mtime = stat.mtime;
        hasher.update(mem.asBytes(&mtime));
    } else if (@hasField(Stat, "mtime_ns")) {
        const mtime_ns = stat.mtime_ns;
        hasher.update(mem.asBytes(&mtime_ns));
    }

    const digest = hasher.final();
    return std.fmt.allocPrint(allocator, "W/\"{x}-{x}\"", .{ size_u64, digest });
}

fn normalizeEtagToken(token: []const u8) []const u8 {
    var trimmed = mem.trim(u8, token, " \t");
    if (mem.startsWith(u8, trimmed, "W/")) {
        trimmed = mem.trim(u8, trimmed[2..], " \t");
    }
    return trimmed;
}

fn ifNoneMatchMatches(if_none_match_header: []const u8, etag: []const u8) bool {
    const normalized_target = normalizeEtagToken(etag);
    var values = mem.splitScalar(u8, if_none_match_header, ',');

    while (values.next()) |raw_value| {
        const token = mem.trim(u8, raw_value, " \t");
        if (token.len == 0) continue;
        if (mem.eql(u8, token, "*")) return true;
        if (mem.eql(u8, normalizeEtagToken(token), normalized_target)) return true;
    }

    return false;
}

test "Server initialization" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator);
    defer server.deinit();

    try std.testing.expectEqual(@as(u16, 8080), server.config.port);
    try std.testing.expectEqualStrings("127.0.0.1", server.config.host);
    try std.testing.expectEqual(@as(u32, 1000), server.config.max_connections);
    try std.testing.expectEqual(@as(u64, 30_000), server.config.request_timeout_ms);
    try std.testing.expectEqual(@as(u64, 60_000), server.config.keep_alive_timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), server.config.threads);
    try std.testing.expect(server.config.keep_alive);
}

test "Context response helpers" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    _ = ctx.status(201);
    try std.testing.expectEqual(@as(u16, 201), ctx.response.status_code);
}

test "Context fileAs helper compile check" {
    const file_as_ptr: *const fn (*Context, []const u8, []const u8) anyerror!Response = Context.fileAs;
    _ = file_as_ptr;
}

test "Context fileWithOptions helper compile check" {
    const file_with_options_ptr: *const fn (*Context, []const u8, FileResponseOptions) anyerror!Response = Context.fileWithOptions;
    _ = file_with_options_ptr;
}

test "Context download helper compile check" {
    const download_ptr: *const fn (*Context, []const u8, ?[]const u8) anyerror!Response = Context.download;
    _ = download_ptr;
}

test "Context noContent helper" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/empty");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    var response = try ctx.noContent();
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 204), response.status.code);
    try std.testing.expect(response.body == null);
}

test "If-None-Match helper supports weak tags and lists" {
    try std.testing.expect(ifNoneMatchMatches("W/\"abc\"", "\"abc\""));
    try std.testing.expect(ifNoneMatchMatches("\"def\", W/\"abc\"", "\"abc\""));
    try std.testing.expect(ifNoneMatchMatches("*", "\"abc\""));
    try std.testing.expect(!ifNoneMatchMatches("\"def\"", "\"abc\""));
}

test "Server with config" {
    const allocator = std.testing.allocator;
    var server = Server.initWithConfig(allocator, .{
        .host = "0.0.0.0",
        .port = 3000,
    });
    defer server.deinit();

    try std.testing.expectEqual(@as(u16, 3000), server.config.port);
    try std.testing.expectEqualStrings("0.0.0.0", server.config.host);
}

test "Context query parsing" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/search?q=zig&lang=en");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("zig", ctx.query("q").?);
    try std.testing.expectEqualStrings("en", ctx.query("lang").?);
    try std.testing.expect(ctx.query("missing") == null);
}

test "Context cookie helpers" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/");
    defer req.deinit();
    try req.headers.set(HeaderName.COOKIE, "session=abc123; theme=dark");

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("abc123", ctx.cookie("session").?);
    try std.testing.expectEqualStrings("dark", ctx.cookie("theme").?);
    try std.testing.expect(ctx.cookie("missing") == null);

    try ctx.setCookie("session", "next", .{ .path = "/", .http_only = true, .same_site = .lax });
    const set_cookie = ctx.response.headers.get(HeaderName.SET_COOKIE).?;
    try std.testing.expect(mem.indexOf(u8, set_cookie, "session=next") != null);

    try ctx.removeCookie("session", .{ .path = "/" });
    const all_set_cookies = try ctx.response.headers.getAll(HeaderName.SET_COOKIE, allocator);
    defer allocator.free(all_set_cookies);
    try std.testing.expect(all_set_cookies.len >= 2);
}

test "Context auth and media helpers" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .POST, "/api");
    defer req.deinit();

    try req.headers.set(HeaderName.AUTHORIZATION, "Bearer demo-token");
    try req.headers.set(HeaderName.CONTENT_TYPE, "application/json; charset=utf-8");
    try req.headers.set(HeaderName.ACCEPT, "application/json, text/*;q=0.8");

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("Bearer demo-token", ctx.authorization().?);
    try std.testing.expectEqualStrings("demo-token", ctx.bearerToken().?);
    try std.testing.expect(ctx.hasContentType("application/json"));
    try std.testing.expect(ctx.isJson());
    try std.testing.expect(!ctx.isFormUrlEncoded());
    try std.testing.expect(ctx.acceptsJson());
    try std.testing.expect(ctx.accepts("text/plain"));
    try std.testing.expect(!ctx.accepts("image/png"));
}

test "Router allowed methods for path" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator);
    defer server.deinit();

    const handler = struct {
        fn h(_: *Context) anyerror!Response {
            return error.TestUnexpectedResult;
        }
    }.h;

    try server.get("/users/:id", handler);
    try server.put("/users/:id", handler);
    try server.delete("/users/:id", handler);

    var methods: [16]types.Method = undefined;
    const count = server.router.allowedMethods("/users/42", &methods);

    try std.testing.expect(count >= 3);

    var has_get = false;
    var has_put = false;
    var has_delete = false;
    for (methods[0..count]) |m| {
        if (m == .GET) has_get = true;
        if (m == .PUT) has_put = true;
        if (m == .DELETE) has_delete = true;
    }

    try std.testing.expect(has_get);
    try std.testing.expect(has_put);
    try std.testing.expect(has_delete);
}

test "Server any() registers all methods" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator);
    defer server.deinit();

    const handler = struct {
        fn h(_: *Context) anyerror!Response {
            return error.TestUnexpectedResult;
        }
    }.h;

    try server.any("/wild", handler);

    const r1 = server.router.find(.GET, "/wild");
    try std.testing.expect(r1 != null);
    allocator.free(r1.?.params);
    const r2 = server.router.find(.POST, "/wild");
    try std.testing.expect(r2 != null);
    allocator.free(r2.?.params);
    const r3 = server.router.find(.TRACE, "/wild");
    try std.testing.expect(r3 != null);
    allocator.free(r3.?.params);
    const r4 = server.router.find(.CONNECT, "/wild");
    try std.testing.expect(r4 != null);
    allocator.free(r4.?.params);
}

test "Server trace/connect helpers register routes" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator);
    defer server.deinit();

    const handler = struct {
        fn h(_: *Context) anyerror!Response {
            return error.TestUnexpectedResult;
        }
    }.h;

    try server.trace("/diag", handler);
    try server.connect("/tunnel", handler);

    const r1 = server.router.find(.TRACE, "/diag");
    try std.testing.expect(r1 != null);
    allocator.free(r1.?.params);
    const r2 = server.router.find(.CONNECT, "/tunnel");
    try std.testing.expect(r2 != null);
    allocator.free(r2.?.params);
}

fn reserveTcpPort() !struct { listener: TcpListener, port: u16 } {
    const addr = try net.Address.parseIp("127.0.0.1", 0);
    var sock = try Socket.createForAddress(addr);
    errdefer sock.close();
    try sock.bind(addr);
    const local = try sock.getLocalAddress();
    return .{ .listener = .{ .socket = sock }, .port = local.getPort() };
}

fn reserveUdpPort() !struct { socket: UdpSocket, port: u16 } {
    const addr = try net.Address.parseIp("127.0.0.1", 0);
    var socket = try UdpSocket.createForAddress(addr);
    errdefer socket.close();
    try socket.bind(addr);
    const local = try socket.getLocalAddress();
    return .{ .socket = socket, .port = local.getPort() };
}

test "Server port conflict strategy fail for TCP" {
    const allocator = std.testing.allocator;

    var reserved = reserveTcpPort() catch return error.SkipZigTest;
    defer reserved.listener.deinit();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = reserved.port,
        .port_conflict = .fail,
        .max_port_tries = 8,
    });
    defer server.deinit();

    const backlog_u32: u32 = @max(server.config.max_connections, 1);
    const backlog: u31 = @intCast(@min(backlog_u32, @as(u32, std.math.maxInt(u31))));

    _ = server.bindTcpListener(backlog) catch |err| {
        try std.testing.expect(err == error.AddressInUse or err == error.BindFailed);
        return;
    };

    return error.TestUnexpectedResult;
}

test "Server port conflict strategy increment for TCP" {
    const allocator = std.testing.allocator;

    var reserved = reserveTcpPort() catch return error.SkipZigTest;
    defer reserved.listener.deinit();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = reserved.port,
        .port_conflict = .increment,
        .max_port_tries = 32,
    });
    defer server.deinit();

    const backlog_u32: u32 = @max(server.config.max_connections, 1);
    const backlog: u31 = @intCast(@min(backlog_u32, @as(u32, std.math.maxInt(u31))));
    try server.bindTcpListener(backlog);

    try std.testing.expect(server.listener != null);
    try std.testing.expect(server.config.port != reserved.port);
}

test "Server port conflict strategy fail for HTTP/3 UDP" {
    const allocator = std.testing.allocator;

    var reserved = try reserveUdpPort();
    defer reserved.socket.close();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = reserved.port,
        .http3_enabled = true,
        .port_conflict = .fail,
        .max_port_tries = 8,
    });
    defer server.deinit();

    _ = server.bindUdpSocket() catch |err| {
        try std.testing.expect(err == error.AddressInUse or err == error.BindFailed);
        return;
    };

    return error.TestUnexpectedResult;
}

test "Server port conflict strategy increment for HTTP/3 UDP" {
    const allocator = std.testing.allocator;

    var reserved = try reserveUdpPort();
    defer reserved.socket.close();

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = reserved.port,
        .http3_enabled = true,
        .port_conflict = .increment,
        .max_port_tries = 32,
    });
    defer server.deinit();

    try server.bindUdpSocket();

    try std.testing.expect(server.udp_socket != null);
    try std.testing.expect(server.config.port != reserved.port);
}

test "Server custom log callback" {
    const allocator = std.testing.allocator;
    const CustomLogger = struct {
        var logged: bool = false;
        fn log_fn(level: LogLevel, message: []const u8) void {
            if (level == .info and std.mem.indexOf(u8, message, "test log message") != null) {
                logged = true;
            }
        }
    };

    const server = Server.initWithConfig(allocator, .{
        .log_fn = CustomLogger.log_fn,
    });
    server.log(.info, "this is a {s} message", .{"test log message"});
    try std.testing.expect(CustomLogger.logged);
}

test "Server with thread pool handles connections" {
    const allocator = std.testing.allocator;
    const Client = @import("../client/client.zig").Client;

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .threads = 2,
        .keep_alive = false,
        .log_fn = &struct {
            fn log_fn(_: LogLevel, _: []const u8) void {}
        }.log_fn,
    });
    defer server.deinit();

    const handler = struct {
        fn h(ctx: *Context) anyerror!Response {
            return ctx.text("hello from worker pool");
        }
    }.h;

    try server.get("/hello", handler);

    const thread = try server.listenInBackground();
    defer {
        server.stop();
        thread.join();
    }

    sleepMs(50);

    const port = server.listeningPort();
    var client = Client.initWithConfig(allocator, .{
        .timeouts = .uniform(5000),
        .keep_alive = false,
    });
    defer client.deinit();

    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/hello", .{port});
    defer allocator.free(url);

    var resp = try client.get(url, .{});
    defer resp.deinit();

    try std.testing.expectEqual(@as(u16, 200), resp.status.code);
    try std.testing.expectEqualStrings("hello from worker pool", resp.text().?);
}

test "Server lifecycle hooks are called" {
    const allocator = std.testing.allocator;
    const HookContext = struct {
        var starting_called: bool = false;
        var started_called: bool = false;
        var stopping_called: bool = false;
        var stopped_called: bool = false;
    };
    HookContext.starting_called = false;
    HookContext.started_called = false;
    HookContext.stopping_called = false;
    HookContext.stopped_called = false;

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .keep_alive = false,
        .log_fn = &struct {
            fn log_fn(_: LogLevel, _: []const u8) void {}
        }.log_fn,
        .on_starting = &struct {
            fn hook(_: *Server) void {
                HookContext.starting_called = true;
            }
        }.hook,
        .on_started = &struct {
            fn hook(_: *Server) void {
                HookContext.started_called = true;
            }
        }.hook,
        .on_stopping = &struct {
            fn hook(_: *Server) void {
                HookContext.stopping_called = true;
            }
        }.hook,
        .on_stopped = &struct {
            fn hook(_: *Server) void {
                HookContext.stopped_called = true;
            }
        }.hook,
    });
    defer server.deinit();

    try server.get("/test", &struct {
        fn h(ctx: *Context) anyerror!Response {
            return ctx.text("ok");
        }
    }.h);

    const thread = try server.listenInBackground();
    defer {
        server.stop();
        thread.join();
    }

    sleepMs(50);
    try std.testing.expect(HookContext.starting_called);
    try std.testing.expect(HookContext.started_called);
    // stopping and stopped are checked after stop() runs in defer.
}

test "Server onError hook is called on handler error" {
    const allocator = std.testing.allocator;
    const ErrorContext = struct {
        var error_called: bool = false;
        var last_err: anyerror = undefined;
    };
    ErrorContext.error_called = false;

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .keep_alive = false,
        .log_fn = &struct {
            fn log_fn(_: LogLevel, _: []const u8) void {}
        }.log_fn,
        .on_error = &struct {
            fn cb(err: anyerror, _: *Context) void {
                ErrorContext.error_called = true;
                ErrorContext.last_err = err;
            }
        }.cb,
    });
    defer server.deinit();

    try server.get("/error", &struct {
        fn h(_: *Context) anyerror!Response {
            return error.TestError;
        }
    }.h);

    const thread = try server.listenInBackground();
    defer {
        server.stop();
        thread.join();
    }

    sleepMs(50);
    const Client = @import("../client/client.zig").Client;
    var client = Client.initWithConfig(allocator, .{
        .timeouts = .uniform(5000),
        .keep_alive = false,
    });
    defer client.deinit();

    const port = server.listeningPort();
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/error", .{port});
    defer allocator.free(url);

    var resp = try client.get(url, .{});
    defer resp.deinit();

    try std.testing.expectEqual(@as(u16, 500), resp.status.code);
    try std.testing.expect(ErrorContext.error_called);
}

test "HTTP/2 server handles request over h2c" {
    const allocator = std.testing.allocator;
    const Client = @import("../client/client.zig").Client;

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .threads = 2,
        .keep_alive = false,
        .http2_enabled = true,
        .log_fn = &struct {
            fn log_fn(_: LogLevel, _: []const u8) void {}
        }.log_fn,
    });
    defer server.deinit();

    try server.get("/h2", &struct {
        fn h(ctx: *Context) anyerror!Response {
            return ctx.text("h2 response");
        }
    }.h);

    const thread = try server.listenInBackground();
    defer {
        server.stop();
        thread.join();
    }
    sleepMs(50);

    const port = server.listeningPort();
    var client = Client.initWithConfig(allocator, .{
        .timeouts = .uniform(5000),
        .keep_alive = false,
        .http2_enabled = true,
    });
    defer client.deinit();

    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/h2", .{port});
    defer allocator.free(url);

    var resp = try client.get(url, .{ .version = .HTTP_2 });
    defer resp.deinit();

    try std.testing.expectEqual(@as(u16, 200), resp.status.code);
    try std.testing.expectEqualStrings("h2 response", resp.text().?);
}

test "HTTP/1.0 server handles close-delimited response" {
    const allocator = std.testing.allocator;
    const Client = @import("../client/client.zig").Client;

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .keep_alive = false,
        .log_fn = &struct {
            fn log_fn(_: LogLevel, _: []const u8) void {}
        }.log_fn,
    });
    defer server.deinit();

    try server.get("/v10", &struct {
        fn h(ctx: *Context) anyerror!Response {
            return ctx.text("http10 response");
        }
    }.h);

    const thread = try server.listenInBackground();
    defer {
        server.stop();
        thread.join();
    }
    sleepMs(50);

    const port = server.listeningPort();
    var client = Client.initWithConfig(allocator, .{
        .timeouts = .uniform(5000),
        .keep_alive = false,
    });
    defer client.deinit();

    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/v10", .{port});
    defer allocator.free(url);

    var resp = try client.get(url, .{ .version = .HTTP_1_0 });
    defer resp.deinit();

    try std.testing.expectEqual(@as(u16, 200), resp.status.code);
    try std.testing.expectEqualStrings("http10 response", resp.text().?);
}

test "HTTP/2 server handles concurrent streams" {
    const allocator = std.testing.allocator;

    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .threads = 2,
        .keep_alive = false,
        .http2_enabled = true,
        .http2_settings = .{
            .header_table_size = 2048,
            .max_concurrent_streams = 2,
            .initial_window_size = 70_000,
            .max_frame_size = 32_768,
            .max_header_list_size = 12_345,
        },
        .request_timeout_ms = 5000,
        .log_fn = &struct {
            fn log_fn(_: LogLevel, _: []const u8) void {}
        }.log_fn,
    });
    defer server.deinit();

    try server.get("/a", &struct {
        fn h(ctx: *Context) anyerror!Response {
            return ctx.text("stream-a");
        }
    }.h);
    try server.get("/b", &struct {
        fn h(ctx: *Context) anyerror!Response {
            return ctx.text("stream-b");
        }
    }.h);

    const thread = try server.listenInBackground();
    defer {
        server.stop();
        thread.join();
    }
    sleepMs(50);

    const port = server.listeningPort();

    // Raw TCP connection for manual HTTP/2 frame construction.
    var stream_manager = h2stream.StreamManager.init(allocator, true);
    defer stream_manager.deinit();

    const conn_addr = net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var tcp_sock = try Socket.create();
    defer tcp_sock.close();
    try tcp_sock.connect(conn_addr);

    // Send connection preface.
    try tcp_sock.writeAll(http.HTTP2_PREFACE);

    // Send initial SETTINGS.
    const settings_payload = http.HTTP2Connection.HTTP2ConnectionSettings{};
    var settings_buf = std.ArrayList(u8).empty;
    defer settings_buf.deinit(allocator);
    try http.encodeSettingsPayload(settings_payload, allocator, &settings_buf);

    const settings_hdr = http.HTTP2FrameHeader{
        .length = @intCast(settings_buf.items.len),
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    };
    const settings_frame = settings_hdr.serialize();
    try tcp_sock.writeAll(&settings_frame);
    try tcp_sock.writeAll(settings_buf.items);

    // Read server SETTINGS.
    var server_settings_buf: [9]u8 = undefined;
    var server_settings_offset: usize = 0;
    while (server_settings_offset < server_settings_buf.len) {
        const n = try tcp_sock.read(server_settings_buf[server_settings_offset..]);
        if (n == 0) return error.UnexpectedEof;
        server_settings_offset += n;
    }
    const server_settings_header = http.HTTP2FrameHeader.parse(server_settings_buf);
    var server_settings_payload: [64]u8 = undefined;
    if (server_settings_header.length > server_settings_payload.len) return error.FrameTooLarge;
    var server_payload_offset: usize = 0;
    while (server_payload_offset < server_settings_header.length) {
        const n = try tcp_sock.read(server_settings_payload[server_payload_offset..server_settings_header.length]);
        if (n == 0) return error.UnexpectedEof;
        server_payload_offset += n;
    }
    var advertised = http.HTTP2Connection.HTTP2ConnectionSettings{};
    try http.applySettingsPayloadForPeer(
        &advertised,
        server_settings_payload[0..server_settings_header.length],
        .server,
    );
    try std.testing.expectEqual(@as(u32, 2048), advertised.header_table_size);
    try std.testing.expectEqual(@as(u32, 2), advertised.max_concurrent_streams);
    try std.testing.expectEqual(@as(u32, 70_000), advertised.initial_window_size);
    try std.testing.expectEqual(@as(u32, 32_768), advertised.max_frame_size);
    try std.testing.expectEqual(@as(u32, 12_345), advertised.max_header_list_size);

    // Send SETTINGS ACK.
    const ack_hdr = http.HTTP2FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = 0x01,
        .stream_id = 0,
    };
    const ack_frame = ack_hdr.serialize();
    try tcp_sock.writeAll(&ack_frame);

    // Build and send HEADERS for stream 1: GET /a
    {
        var hdrs = std.ArrayList(hpack.HeaderEntry).empty;
        defer hdrs.deinit(allocator);
        try hdrs.append(allocator, .{ .name = ":method", .value = "GET" });
        try hdrs.append(allocator, .{ .name = ":path", .value = "/a" });
        try hdrs.append(allocator, .{ .name = ":scheme", .value = "http" });
        try hdrs.append(allocator, .{ .name = ":authority", .value = "127.0.0.1" });

        const hblock = try h2stream.buildHeadersAndContinuations(
            &stream_manager,
            1,
            hdrs.items,
            null,
            16384,
            true,
            allocator,
        );
        defer allocator.free(hblock);
        try tcp_sock.writeAll(hblock);
    }

    // Build and send HEADERS for stream 3: GET /b (concurrent).
    {
        var hdrs = std.ArrayList(hpack.HeaderEntry).empty;
        defer hdrs.deinit(allocator);
        try hdrs.append(allocator, .{ .name = ":method", .value = "GET" });
        try hdrs.append(allocator, .{ .name = ":path", .value = "/b" });
        try hdrs.append(allocator, .{ .name = ":scheme", .value = "http" });
        try hdrs.append(allocator, .{ .name = ":authority", .value = "127.0.0.1" });

        const hblock = try h2stream.buildHeadersAndContinuations(
            &stream_manager,
            3,
            hdrs.items,
            null,
            16384,
            true,
            allocator,
        );
        defer allocator.free(hblock);
        try tcp_sock.writeAll(hblock);
    }

    // Read responses: expect HEADERS + DATA frames for streams 1 and 3.
    var found_stream_1 = false;
    var found_stream_3 = false;
    var attempts: u32 = 0;
    while ((!found_stream_1 or !found_stream_3) and attempts < 40) {
        var hdr_buf: [9]u8 = undefined;
        const n = tcp_sock.read(&hdr_buf) catch break;
        if (n == 0) break;
        if (n < 9) continue;

        const fhdr = http.HTTP2FrameHeader.parse(hdr_buf);
        if (fhdr.stream_id == 1) found_stream_1 = true;
        if (fhdr.stream_id == 3) found_stream_3 = true;

        // Skip payload.
        if (fhdr.length > 0) {
            var skip_buf: [4096]u8 = undefined;
            var remaining: u32 = fhdr.length;
            while (remaining > 0) {
                const to_read = @min(remaining, @as(u32, @intCast(skip_buf.len)));
                const got = tcp_sock.read(skip_buf[0..to_read]) catch break;
                if (got == 0) break;
                remaining -= @intCast(got);
            }
        }
        attempts += 1;
    }

    try std.testing.expect(found_stream_1);
    try std.testing.expect(found_stream_3);
}

fn streamingTestSocketPair() ![2]Socket {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var handles: [2]std.posix.socket_t = undefined;
        const rc = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &handles);
        if (std.posix.errno(rc) != .SUCCESS) return error.SocketPairFailed;
        return .{
            Socket.fromHandle(handles[0]),
            Socket.fromHandle(handles[1]),
        };
    }
}

test "TLS streaming headers preserve values larger than one record" {
    const Mode = enum { chunked, raw };
    const modes = [_]Mode{ .chunked, .raw };
    const key = [_]u8{0x5a} ** 32;
    const iv = [_]u8{0xa5} ** 12;

    for (modes) |mode| {
        const large_value = try std.testing.allocator.alloc(u8, 20 * 1024 + 37);
        defer std.testing.allocator.free(large_value);
        @memset(large_value, 'v');

        var headers = Headers.init(std.testing.allocator);
        defer headers.deinit();
        try headers.append("X-Large", large_value);

        const sockets = try streamingTestSocketPair();
        var sender = sockets[0];
        defer sender.close();
        var receiver = sockets[1];
        defer receiver.close();

        var tls_sender = tls_mod.Connection{
            .allocator = std.testing.allocator,
            .socket = &sender,
            .tls_version = .tls_1_3,
            .connected = true,
            .app_write_key = key,
            .app_write_iv = iv,
            .cipher_suite = .AES_128_GCM_SHA256,
        };
        var tls_receiver = tls_mod.Connection{
            .allocator = std.testing.allocator,
            .socket = &receiver,
            .tls_version = .tls_1_3,
            .connected = true,
            .app_read_key = key,
            .app_read_iv = iv,
            .cipher_suite = .AES_128_GCM_SHA256,
        };
        var stream_writer = StreamWriter.fromTLS(std.testing.allocator, &tls_sender);

        var request = try Request.init(std.testing.allocator, .GET, "/");
        defer request.deinit();
        var context = Context.init(std.testing.allocator, &request);
        defer context.deinit();
        try context.data.put("__stream_writer", @ptrCast(&stream_writer));

        const Writer = struct {
            context: *Context,
            headers: *const Headers,
            sender: *Socket,
            mode: Mode,
            failure: ?anyerror = null,

            fn run(self: *@This()) void {
                _ = switch (self.mode) {
                    .chunked => self.context.startStreaming(200, self.headers),
                    .raw => self.context.startRawStreaming(200, self.headers),
                } catch |err| {
                    self.failure = err;
                    return;
                };
                self.sender.shutdownWrite() catch |err| {
                    self.failure = err;
                };
            }
        };
        var writer = Writer{
            .context = &context,
            .headers = &headers,
            .sender = &sender,
            .mode = mode,
        };
        const writer_thread = try std.Thread.spawn(.{}, Writer.run, .{&writer});
        var writer_joined = false;
        defer if (!writer_joined) writer_thread.join();

        var expected = std.ArrayList(u8).empty;
        defer expected.deinit(std.testing.allocator);
        try expected.appendSlice(std.testing.allocator, "HTTP/1.1 200\r\nX-Large: ");
        try expected.appendSlice(std.testing.allocator, large_value);
        try expected.appendSlice(std.testing.allocator, "\r\n");
        if (mode == .chunked) {
            try expected.appendSlice(std.testing.allocator, "Transfer-Encoding: chunked\r\n");
        }
        try expected.appendSlice(std.testing.allocator, "\r\n");

        var actual = std.ArrayList(u8).empty;
        defer actual.deinit(std.testing.allocator);
        var read_buf: [1024]u8 = undefined;
        while (actual.items.len < expected.items.len) {
            const n = try tls_receiver.read(&read_buf);
            if (n == 0) return error.UnexpectedEof;
            try actual.appendSlice(std.testing.allocator, read_buf[0..n]);
        }
        writer_thread.join();
        writer_joined = true;
        if (writer.failure) |err| return err;

        try std.testing.expect(context.streaming_done);
        try std.testing.expect(tls_sender.write_seq > 1);
        try std.testing.expectEqualSlices(u8, expected.items, actual.items);
    }
}

test "Server rejects public HTTP3 before binding" {
    var server = Server.initWithConfig(std.testing.allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .http3_enabled = true,
    });
    defer server.deinit();
    try std.testing.expectError(error.UnsupportedHttpVersion, server.listenInBackground());
    try std.testing.expect(server.listener == null);
    try std.testing.expect(server.udp_socket == null);
}

test "HTTP2 server validates TLS preface and disables push" {
    try Server.validateHTTP2Preface(http.HTTP2_PREFACE);
    try std.testing.expectError(
        error.ProtocolError,
        Server.validateHTTP2Preface("GET / HTTP/1.1\r\n\r\n"),
    );

    var server = Server.init(std.testing.allocator);
    defer server.deinit();
    var conn: http.HTTP2Connection = undefined;
    var manager = h2stream.StreamManager.init(std.testing.allocator, false);
    defer manager.deinit();
    try std.testing.expectError(
        error.PushDisabled,
        server.pushPromise(&conn, &manager, 1, .GET, "/", null),
    );
}

test "HTTP2 server rejects malformed request header blocks" {
    var server = Server.init(std.testing.allocator);
    defer server.deinit();

    const cases = [_][]const hpack.HeaderEntry{
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":method", .value = "POST" },
        },
        &.{
            .{ .name = "x-first", .value = "value" },
            .{ .name = ":path", .value = "/" },
        },
        &.{.{ .name = "X-Upper", .value = "value" }},
        &.{.{ .name = "connection", .value = "keep-alive" }},
        &.{.{ .name = ":unknown", .value = "value" }},
    };

    for (cases) |entries| {
        var ctx = Server.H2ServerStreamContext.init(std.testing.allocator, 1);
        defer ctx.deinit(std.testing.allocator);
        try std.testing.expectError(
            error.ProtocolError,
            server.parseHeaders(
                hpack.HeaderEntry,
                entries,
                &ctx.request_headers,
                &ctx.method_raw,
                &ctx.method_owned,
                &ctx.path_raw,
                &ctx.path_owned,
                &ctx.scheme_raw,
                &ctx.scheme_owned,
                &ctx.authority_raw,
                &ctx.authority_owned,
            ),
        );
    }
}

test "HTTP2 server preserves custom methods and validates content length" {
    var server = Server.init(std.testing.allocator);
    defer server.deinit();
    var ctx = Server.H2ServerStreamContext.init(std.testing.allocator, 1);
    defer ctx.deinit(std.testing.allocator);
    const entries = [_]hpack.HeaderEntry{
        .{ .name = ":method", .value = "PURGE" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/cache" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "content-length", .value = "5, 5" },
    };
    try server.parseHeaders(
        hpack.HeaderEntry,
        &entries,
        &ctx.request_headers,
        &ctx.method_raw,
        &ctx.method_owned,
        &ctx.path_raw,
        &ctx.path_owned,
        &ctx.scheme_raw,
        &ctx.scheme_owned,
        &ctx.authority_raw,
        &ctx.authority_owned,
    );
    try std.testing.expectEqualStrings("PURGE", ctx.method_raw);
    try std.testing.expect(types.Method.fromString(ctx.method_raw) == null);
    try std.testing.expectEqual(@as(?u64, 5), try Server.requestContentLength(&ctx.request_headers));
    ctx.expected_content_length = 5;
    ctx.received_body_bytes = 4;
    try std.testing.expectError(error.RequestBodyUnderrun, Server.validateRequestBodyLength(&ctx));
    ctx.received_body_bytes = 6;
    try std.testing.expectError(error.RequestBodyOverrun, Server.validateRequestBodyLength(&ctx));
    ctx.received_body_bytes = 5;
    try Server.validateRequestBodyLength(&ctx);

    try ctx.request_headers.append("content-length", "6");
    try std.testing.expectError(
        error.InvalidContentLength,
        Server.requestContentLength(&ctx.request_headers),
    );

    try std.testing.expectError(
        error.ProtocolError,
        Server.enforceContinuation(1, .{
            .length = 8,
            .frame_type = .ping,
            .flags = 0,
            .stream_id = 0,
        }),
    );
    try std.testing.expectError(
        error.ProtocolError,
        Server.enforceContinuation(1, .{
            .length = 0,
            .frame_type = .continuation,
            .flags = 0x04,
            .stream_id = 3,
        }),
    );
    try Server.enforceContinuation(1, .{
        .length = 0,
        .frame_type = .continuation,
        .flags = 0x04,
        .stream_id = 1,
    });
    const bad_trailers = [_]hpack.HeaderEntry{
        .{ .name = "content-length", .value = "5" },
    };
    try std.testing.expectError(
        error.ProtocolError,
        Server.validateRequestTrailers(hpack.HeaderEntry, &bad_trailers),
    );
}

test "HTTP2 server response obeys stream and connection send windows" {
    const allocator = std.testing.allocator;
    var server = Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .http2_enabled = true,
        .request_timeout_ms = 5_000,
        .log_fn = &struct {
            fn logFn(_: LogLevel, _: []const u8) void {}
        }.logFn,
    });
    defer server.deinit();
    try server.get("/large", &struct {
        const body = "x" ** 70_000;
        fn handler(ctx: *Context) anyerror!Response {
            return ctx.text(body);
        }
    }.handler);
    const server_thread = try server.listenInBackground();
    defer {
        server.stop();
        server_thread.join();
    }

    var socket = try Socket.create();
    defer socket.close();
    try socket.connect(net.Address.initIp4(.{ 127, 0, 0, 1 }, server.listeningPort()));

    const Helpers = struct {
        fn readExact(sock: *Socket, output: []u8) !void {
            var offset: usize = 0;
            while (offset < output.len) {
                const n = try sock.read(output[offset..]);
                if (n == 0) return error.UnexpectedEof;
                offset += n;
            }
        }

        fn readFrame(sock: *Socket, payload: []u8) !http.HTTP2FrameHeader {
            var raw: [9]u8 = undefined;
            try readExact(sock, &raw);
            const header = http.HTTP2FrameHeader.parse(raw);
            if (header.length > payload.len) return error.FrameTooLarge;
            try readExact(sock, payload[0..header.length]);
            return header;
        }

        fn writeWindowUpdate(sock: *Socket, stream_id: u31, increment: u31) !void {
            const payload = h2stream.buildWindowUpdatePayload(increment);
            const header = http.HTTP2FrameHeader{
                .length = payload.len,
                .frame_type = .window_update,
                .flags = 0,
                .stream_id = stream_id,
            };
            const serialized = header.serialize();
            try sock.writeAll(&serialized);
            try sock.writeAll(&payload);
        }
    };

    try socket.writeAll(http.HTTP2_PREFACE);
    var client_settings = http.HTTP2Connection.HTTP2ConnectionSettings{};
    client_settings.initial_window_size = 32_768;
    var settings_payload = std.ArrayList(u8).empty;
    defer settings_payload.deinit(allocator);
    try http.encodeSettingsPayload(client_settings, allocator, &settings_payload);
    const client_settings_header = (http.HTTP2FrameHeader{
        .length = @intCast(settings_payload.items.len),
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }).serialize();
    try socket.writeAll(&client_settings_header);
    try socket.writeAll(settings_payload.items);

    var payload: [64 * 1024]u8 = undefined;
    const server_settings = try Helpers.readFrame(&socket, &payload);
    try std.testing.expectEqual(http.HTTP2FrameType.settings, server_settings.frame_type);
    const settings_ack = (http.HTTP2FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = 0x01,
        .stream_id = 0,
    }).serialize();
    try socket.writeAll(&settings_ack);

    var manager = h2stream.StreamManager.init(allocator, true);
    defer manager.deinit();
    const request_headers = [_]hpack.HeaderEntry{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/large" },
        .{ .name = ":authority", .value = "127.0.0.1" },
    };
    const request_frames = try h2stream.buildHeadersAndContinuations(
        &manager,
        1,
        &request_headers,
        null,
        16_384,
        true,
        allocator,
    );
    defer allocator.free(request_frames);
    try socket.writeAll(request_frames);

    var total: usize = 0;
    var saw_end = false;
    while (!saw_end) {
        const frame = try Helpers.readFrame(&socket, &payload);
        if (frame.frame_type != .data) continue;
        total += frame.length;
        if (total == 32_768) {
            try std.testing.expect(!socket.waitReadable(50));
            try Helpers.writeWindowUpdate(&socket, 1, 40_000);
        } else if (total == 65_535) {
            try std.testing.expect(!socket.waitReadable(50));
            try Helpers.writeWindowUpdate(&socket, 0, 10_000);
        }
        saw_end = (frame.flags & 0x01) != 0;
    }
    try std.testing.expectEqual(@as(usize, 70_000), total);

    const late_reset = h2stream.buildRstStreamFrame(1, .cancel);
    try socket.writeAll(&late_reset);
    try Helpers.writeWindowUpdate(&socket, 1, 1);
    const ping_header = (http.HTTP2FrameHeader{
        .length = 8,
        .frame_type = .ping,
        .flags = 0,
        .stream_id = 0,
    }).serialize();
    try socket.writeAll(&ping_header);
    try socket.writeAll("lateping");
    while (true) {
        const frame = try Helpers.readFrame(&socket, &payload);
        if (frame.frame_type == .ping and (frame.flags & 0x01) != 0) {
            try std.testing.expectEqualStrings("lateping", payload[0..frame.length]);
            break;
        }
    }
}

test "HTTP2 server send-window pump resets terminal stream state" {
    const rst = h2stream.buildRstStreamFrame(1, .cancel);
    const Fixture = struct {
        input: []const u8,
        offset: usize = 0,

        fn read(context_ptr: *anyopaque, output: []u8) !usize {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            if (self.offset == self.input.len) return 0;
            const amount = @min(output.len, self.input.len - self.offset);
            @memcpy(output[0..amount], self.input[self.offset..][0..amount]);
            self.offset += amount;
            return amount;
        }

        fn write(_: *anyopaque, data: []const u8) !usize {
            return data.len;
        }
    };
    var fixture = Fixture{ .input = &rst };
    var conn = http.HTTP2Connection.init(
        std.testing.allocator,
        .{ .context = &fixture, .readFn = Fixture.read },
        .{ .context = &fixture, .writeFn = Fixture.write },
    );
    var manager = h2stream.StreamManager.init(std.testing.allocator, false);
    defer manager.deinit();
    const stream = try manager.getOrCreateStream(1);
    try stream.open();
    stream.receiveEndStream();
    var server = Server.init(std.testing.allocator);
    defer server.deinit();
    var frame_context = IoContext.init(.{});
    var pending_frames = std.ArrayList(http.HTTP2Connection.Frame).empty;
    defer {
        for (pending_frames.items) |*pending| pending.deinit(std.testing.allocator);
        pending_frames.deinit(std.testing.allocator);
    }
    var pending_bytes: usize = 0;
    var queued_continuation: ?u31 = null;
    try std.testing.expectError(
        error.StreamReset,
        server.pumpHTTP2SendWindow(
            &conn,
            &manager,
            1,
            &frame_context,
            null,
            &pending_frames,
            &pending_bytes,
            &queued_continuation,
            1,
        ),
    );
    try std.testing.expectEqual(h2stream.StreamState.closed, stream.state);
}

test "HTTP2 server send-window pump queues multiplexed stream work" {
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(std.testing.allocator);
    const other_headers = (http.HTTP2FrameHeader{
        .length = 0,
        .frame_type = .headers,
        .flags = 0x05,
        .stream_id = 3,
    }).serialize();
    try wire.appendSlice(std.testing.allocator, &other_headers);
    const update_payload = h2stream.buildWindowUpdatePayload(5);
    const update_header = (http.HTTP2FrameHeader{
        .length = update_payload.len,
        .frame_type = .window_update,
        .flags = 0,
        .stream_id = 1,
    }).serialize();
    try wire.appendSlice(std.testing.allocator, &update_header);
    try wire.appendSlice(std.testing.allocator, &update_payload);

    const Fixture = struct {
        input: []const u8,
        offset: usize = 0,
        fn read(context_ptr: *anyopaque, output: []u8) !usize {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            if (self.offset == self.input.len) return 0;
            const amount = @min(output.len, self.input.len - self.offset);
            @memcpy(output[0..amount], self.input[self.offset..][0..amount]);
            self.offset += amount;
            return amount;
        }
        fn write(_: *anyopaque, data: []const u8) !usize {
            return data.len;
        }
    };
    var fixture = Fixture{ .input = wire.items };
    var conn = http.HTTP2Connection.init(
        std.testing.allocator,
        .{ .context = &fixture, .readFn = Fixture.read },
        .{ .context = &fixture, .writeFn = Fixture.write },
    );
    var manager = h2stream.StreamManager.init(std.testing.allocator, false);
    defer manager.deinit();
    const response_stream = try manager.getOrCreateStream(1);
    try response_stream.open();
    response_stream.receiveEndStream();
    response_stream.send_window = 0;
    var server = Server.init(std.testing.allocator);
    defer server.deinit();
    var frame_context = IoContext.init(.{});
    var pending_frames = std.ArrayList(http.HTTP2Connection.Frame).empty;
    defer {
        for (pending_frames.items) |*pending| pending.deinit(std.testing.allocator);
        pending_frames.deinit(std.testing.allocator);
    }
    var pending_bytes: usize = 0;
    var queued_continuation: ?u31 = null;

    try server.pumpHTTP2SendWindow(
        &conn,
        &manager,
        1,
        &frame_context,
        null,
        &pending_frames,
        &pending_bytes,
        &queued_continuation,
        1,
    );
    try std.testing.expectEqual(@as(usize, 1), pending_frames.items.len);
    try std.testing.expectEqual(@as(i32, 0), response_stream.send_window);
    try server.pumpHTTP2SendWindow(
        &conn,
        &manager,
        1,
        &frame_context,
        null,
        &pending_frames,
        &pending_bytes,
        &queued_continuation,
        1,
    );
    try std.testing.expectEqual(@as(i32, 5), response_stream.send_window);
}

test "Server connection owner closes accepted HTTP1 sockets" {
    var server = Server.initWithConfig(std.testing.allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .keep_alive = false,
        .log_fn = &struct {
            fn logFn(_: LogLevel, _: []const u8) void {}
        }.logFn,
    });
    defer server.deinit();
    try server.get("/close", &struct {
        fn handler(ctx: *Context) anyerror!Response {
            return ctx.text("ok");
        }
    }.handler);
    const thread = try server.listenInBackground();
    defer {
        server.stop();
        thread.join();
    }

    var socket = try Socket.create();
    defer socket.close();
    try socket.connect(net.Address.initIp4(.{ 127, 0, 0, 1 }, server.listeningPort()));
    try socket.writeAll(
        "GET /close HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    try socket.setRecvTimeout(2_000);
    var response: [1024]u8 = undefined;
    var length: usize = 0;
    while (mem.indexOf(u8, response[0..length], "\r\n\r\n") == null or
        mem.indexOf(u8, response[0..length], "\r\n\r\n").? + 6 > length)
    {
        const n = try socket.recv(response[length..]);
        if (n == 0) return error.UnexpectedEof;
        length += n;
    }
    try std.testing.expectEqual(@as(usize, 0), try socket.recv(&response));
}

test "cleartext HTTP2 preface probe has one bounded deadline" {
    var server = Server.initWithConfig(std.testing.allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .http2_enabled = true,
        .request_timeout_ms = 50,
        .log_fn = &struct {
            fn logFn(_: LogLevel, _: []const u8) void {}
        }.logFn,
    });
    defer server.deinit();
    const thread = try server.listenInBackground();
    defer {
        server.stop();
        thread.join();
    }

    var socket = try Socket.create();
    defer socket.close();
    try socket.connect(net.Address.initIp4(.{ 127, 0, 0, 1 }, server.listeningPort()));
    try socket.writeAll("PRI");
    try socket.setRecvTimeout(2_000);
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try socket.recv(&byte));
}

test "HTTP2 trailer continuation uses one anchored header-block deadline" {
    var server = Server.initWithConfig(std.testing.allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .http2_enabled = true,
        .request_timeout_ms = 50,
        .log_fn = &struct {
            fn logFn(_: LogLevel, _: []const u8) void {}
        }.logFn,
    });
    defer server.deinit();
    const thread = try server.listenInBackground();
    defer {
        server.stop();
        thread.join();
    }
    var socket = try Socket.create();
    defer socket.close();
    try socket.connect(net.Address.initIp4(.{ 127, 0, 0, 1 }, server.listeningPort()));
    try socket.writeAll(http.HTTP2_PREFACE);

    var settings_payload = std.ArrayList(u8).empty;
    defer settings_payload.deinit(std.testing.allocator);
    try http.encodeSettingsPayload(
        .{},
        std.testing.allocator,
        &settings_payload,
    );
    const settings_header = (http.HTTP2FrameHeader{
        .length = @intCast(settings_payload.items.len),
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }).serialize();
    try socket.writeAll(&settings_header);
    try socket.writeAll(settings_payload.items);

    const Helpers = struct {
        fn readExact(sock: *Socket, output: []u8) !void {
            var offset: usize = 0;
            while (offset < output.len) {
                const n = try sock.recv(output[offset..]);
                if (n == 0) return error.UnexpectedEof;
                offset += n;
            }
        }
        fn readFrame(sock: *Socket, payload: []u8) !http.HTTP2FrameHeader {
            var raw: [9]u8 = undefined;
            try readExact(sock, &raw);
            const header = http.HTTP2FrameHeader.parse(raw);
            if (header.length > payload.len) return error.FrameTooLarge;
            try readExact(sock, payload[0..header.length]);
            return header;
        }
    };
    var payload: [256]u8 = undefined;
    _ = try Helpers.readFrame(&socket, &payload);
    _ = try Helpers.readFrame(&socket, &payload);

    var encoder = hpack.HPACKContext.init(std.testing.allocator);
    defer encoder.deinit();
    const fields = [_]hpack.HeaderEntry{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "127.0.0.1" },
    };
    const block = try hpack.encodeHeaders(&encoder, &fields, std.testing.allocator);
    defer std.testing.allocator.free(block);
    const headers_frame = (http.HTTP2FrameHeader{
        .length = @intCast(block.len),
        .frame_type = .headers,
        .flags = 0x04,
        .stream_id = 1,
    }).serialize();
    try socket.writeAll(&headers_frame);
    try socket.writeAll(block);
    const trailers = try hpack.encodeHeaders(
        &encoder,
        &.{.{ .name = "x-trailer", .value = "value", .representation = .without_indexing }},
        std.testing.allocator,
    );
    defer std.testing.allocator.free(trailers);
    const trailer_frame = (http.HTTP2FrameHeader{
        .length = @intCast(trailers.len),
        .frame_type = .headers,
        .flags = 0x01,
        .stream_id = 1,
    }).serialize();
    try socket.writeAll(&trailer_frame);
    try socket.writeAll(trailers);
    try socket.setRecvTimeout(2_000);
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try socket.recv(&byte));
}
