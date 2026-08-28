const std = @import("std");
const httpx = @import("httpx");

fn logRequest(request: *httpx.Request, attempt: *const httpx.AttemptContext, context: ?*anyopaque) anyerror!void {
    _ = context;
    std.debug.print("[Interceptor] Request #{d}.{d}: {s} {s}\n", .{
        attempt.logical_request_id,
        attempt.attempt,
        request.method.toString(),
        request.uri.path,
    });
}

fn logResponse(response: *httpx.Response, attempt: *const httpx.AttemptContext, context: ?*anyopaque) anyerror!void {
    _ = context;
    std.debug.print("[Interceptor] Response #{d}.{d}: {d} {s}\n", .{
        attempt.logical_request_id,
        attempt.attempt,
        response.status.code,
        response.status.phrase,
    });
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = httpx.Client.initWithConfig(allocator, .{
        .user_agent = "httpx.zig-interceptor-demo/1.0",
        .policy = httpx.ClientPolicy.managed(),
    });
    defer client.deinit();

    try client.addInterceptor(.{
        .request_fn = logRequest,
        .response_fn = logResponse,
        .context = null,
    });

    std.debug.print("Interceptor registered\n", .{});
}
