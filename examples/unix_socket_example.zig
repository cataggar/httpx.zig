//! Unix Domain Socket Example
//!
//! Demonstrates httpx.zig's IPC (Inter-Process Communication) support:
//! - Running an HTTP server listening on a Unix domain socket path
//! - Connecting an HTTP client to the Unix domain socket path
//! - Executing GET requests and parsing responses

const std = @import("std");
const httpx = @import("httpx");
const builtin = @import("builtin");

fn sleepMs(ms: i64) void {
    const io = std.Io.Threaded.global_single_threaded.io();
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(ms), .real) catch {};
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Unix Domain Socket Example ===\n\n", .{});

    const socket_path = "httpx-ipc.sock";

    // 1. Initialize and configure HTTP Server on Unix Socket
    std.debug.print("Initializing server on: {s}...\n", .{socket_path});
    var server = httpx.Server.initWithConfig(allocator, .{
        .unix_path = socket_path,
    });
    defer server.deinit();

    // Register a test route
    try server.get("/ipc-status", struct {
        fn h(ctx: *httpx.Context) anyerror!httpx.Response {
            return ctx.json(.{
                .status = "connected",
                .transport = "unix_domain_socket",
                .os = @tagName(builtin.os.tag),
            });
        }
    }.h);

    // 2. Start the server asynchronously
    const thread = server.listenInBackground() catch |err| {
        std.debug.print("AF_UNIX sockets are not supported or bound on this platform/runner: {}\nSkipping example.\n", .{err});
        return;
    };
    defer thread.join();
    defer server.stop();

    // Give server a moment to bind and listen
    sleepMs(50);

    // 3. Initialize HTTP Client with unix_socket_path
    std.debug.print("Connecting client to Unix socket: {s}...\n", .{socket_path});
    var client = httpx.Client.initWithConfig(allocator, httpx.ClientConfig.defaults()
        .withUnixSocket(socket_path)
    );
    defer client.deinit();

    // Make an HTTP GET request over the Unix socket
    std.debug.print("Sending GET request over Unix socket...\n", .{});
    var resp = client.get("http://localhost/ipc-status", .{}) catch |err| {
        std.debug.print("Failed to execute request over Unix socket: {}\nAF_UNIX is likely not supported on this OS version/runner. Skipping.\n", .{err});
        return;
    };
    defer resp.deinit();

    // 4. Print results
    std.debug.print("\nResponse Status: {d}\n", .{resp.status.code});
    std.debug.print("Response Body:\n{s}\n", .{resp.text().?});

    std.debug.print("\n=== Unix Domain Socket Example Complete ===\n", .{});
}
