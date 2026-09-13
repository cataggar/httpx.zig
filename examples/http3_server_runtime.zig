const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    var server = httpx.Server.initWithConfig(gpa.allocator(), .{
        .host = "127.0.0.1",
        .port = 0,
        .http3_enabled = true,
    });
    defer server.deinit();

    if (server.listenInBackground()) |thread| {
        server.stop();
        thread.join();
        return error.ExpectedHttp3Rejection;
    } else |err| switch (err) {
        error.UnsupportedHttpVersion => std.debug.print(
            "HTTP/3 server transport is unavailable until authenticated QUIC is implemented.\n",
            .{},
        ),
        else => return err,
    }
}
