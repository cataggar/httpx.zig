//! Mock HTTP Server for Testing with httpx.zig
//!
//! Provides an in-process mock HTTP server for unit and integration tests.
//! The mock server runs a real TCP listener on a random free port, allowing
//! you to test your httpx.zig client code without hitting real network endpoints.
//!
//! ## Features
//! - Programmatic request expectations and response stubs
//! - Ordered or unordered matching
//! - Request capture for assertions
//! - Automatic cleanup on deinit
//!
//! ## Example
//! ```zig
//! var mock = try httpx.MockServer.init(allocator);
//! defer mock.deinit();
//!
//! mock.stub(.GET, "/api/users", 200, "application/json", "[{\"id\":1}]");
//!
//! var client = httpx.Client.init(allocator);
//! defer client.deinit();
//!
//! var resp = try client.get(mock.urlFor("/api/users"), .{});
//! defer resp.deinit();
//! try std.testing.expectEqual(@as(u16, 200), resp.status.code);
//! try std.testing.expectEqualStrings("[{\"id\":1}]", resp.text().?);
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;

const server_mod = @import("../server/server.zig");
const types = @import("../core/types.zig");

/// A stub response configured for a specific method+path.
pub const Stub = struct {
    method: types.Method,
    path: []const u8,
    status: u16,
    content_type: []const u8,
    body: []const u8,
    headers: ?[]const @import("../core/headers.zig").Header = null,
};

/// A recorded incoming request.
pub const RecordedRequest = struct {
    method: types.Method,
    path: []const u8,
    body: ?[]const u8,
};

/// In-process mock HTTP server backed by a real httpx.Server.
pub const MockServer = struct {
    allocator: Allocator,
    server: server_mod.Server,
    thread: ?std.Thread = null,
    port: u16 = 0,
    stubs: std.ArrayList(Stub),
    recorded: std.ArrayList(RecordedRequest),

    const Self = @This();

    /// Creates and starts a mock server on a free port.
    pub fn init(allocator: Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .server = server_mod.Server.initWithConfig(allocator, .{
                .host = "127.0.0.1",
                .port = 0,
                .port_conflict = .increment,
                .keep_alive = false,
                .request_timeout_ms = 5_000,
            }),
            .stubs = std.ArrayList(Stub).init(allocator),
            .recorded = std.ArrayList(RecordedRequest).init(allocator),
        };

        // Register a global catch-all handler
        self.server.global(globalHandler);

        self.thread = try self.server.listenInBackground();
        self.port = self.server.listeningPort();

        // Store self reference for the handler (via a comptime global)
        _mock_instance = self;
        return self;
    }

    /// Stops the server and frees resources.
    pub fn deinit(self: *Self) void {
        self.server.stop();
        if (self.thread) |t| t.join();
        self.server.deinit();
        self.stubs.deinit();
        self.recorded.deinit();
        _mock_instance = null;
        self.allocator.destroy(self);
    }

    /// Registers a stub response for a method and path.
    pub fn stub(
        self: *Self,
        method: types.Method,
        path: []const u8,
        status_code: u16,
        content_type: []const u8,
        body: []const u8,
    ) void {
        self.stubs.append(.{
            .method = method,
            .path = path,
            .status = status_code,
            .content_type = content_type,
            .body = body,
            .headers = null,
        }) catch {};
    }

    /// Registers a stub response with custom headers.
    pub fn stubWithHeaders(
        self: *Self,
        method: types.Method,
        path: []const u8,
        status_code: u16,
        content_type: []const u8,
        body: []const u8,
        headers: []const @import("../core/headers.zig").Header,
    ) void {
        self.stubs.append(.{
            .method = method,
            .path = path,
            .status = status_code,
            .content_type = content_type,
            .body = body,
            .headers = headers,
        }) catch {};
    }

    /// Returns the full URL for a given path on this mock server.
    pub fn urlFor(self: *const Self, path: []const u8) []u8 {
        return std.fmt.allocPrint(self.allocator, "http://127.0.0.1:{d}{s}", .{ self.port, path }) catch "";
    }

    /// Returns the number of requests captured.
    pub fn requestCount(self: *const Self) usize {
        return self.recorded.items.len;
    }

    /// Returns the nth recorded request (0-indexed).
    pub fn requestAt(self: *const Self, index: usize) ?RecordedRequest {
        if (index >= self.recorded.items.len) return null;
        return self.recorded.items[index];
    }

    /// Clears all recorded requests.
    pub fn clearRecorded(self: *Self) void {
        self.recorded.clearRetainingCapacity();
    }
};

// Global instance pointer used by the handler (single mock per process at a time).
var _mock_instance: ?*MockServer = null;

fn globalHandler(ctx: *server_mod.Context) anyerror!server_mod.Response {
    const mock = _mock_instance orelse return ctx.status(503).text("No mock instance");

    // Record request
    mock.recorded.append(.{
        .method = ctx.request.method,
        .path = ctx.request.uri.path,
        .body = ctx.request.body,
    }) catch {};

    // Find matching stub
    for (mock.stubs.items) |s| {
        if (s.method == ctx.request.method and std.mem.eql(u8, s.path, ctx.request.uri.path)) {
            _ = try ctx.response.header("Content-Type", s.content_type);
            _ = ctx.response.status(s.status);
            _ = ctx.response.body(s.body);
            if (s.headers) |hdrs| {
                for (hdrs) |h| {
                    _ = try ctx.response.header(h.name, h.value);
                }
            }
            return ctx.response.build();
        }
    }

    return ctx.status(404).text("No stub found");
}

test "MockServer types compile" {
    _ = MockServer;
    _ = Stub;
    _ = RecordedRequest;
}

test "MockServer with custom headers" {
    const allocator = std.testing.allocator;
    var mock = try MockServer.init(allocator);
    defer mock.deinit();

    const custom_headers = [_]@import("../core/headers.zig").Header{
        .{ .name = "X-Mock-Header", .value = "Value1" },
        .{ .name = "Server", .value = "MockServer/1.2" },
    };

    mock.stubWithHeaders(.GET, "/custom", 200, "text/plain", "OK", &custom_headers);

    const client_mod = @import("../client/client.zig");
    var client = client_mod.Client.init(allocator);
    defer client.deinit();

    const url = mock.urlFor("/custom");
    defer allocator.free(url);

    var resp = try client.get(url, .{});
    defer resp.deinit();

    try std.testing.expectEqual(@as(u16, 200), resp.status.code);
    try std.testing.expectEqualStrings("Value1", resp.headers.get("X-Mock-Header").?);
    try std.testing.expectEqualStrings("MockServer/1.2", resp.headers.get("Server").?);
}
