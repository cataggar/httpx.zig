const std = @import("std");
const httpx = @import("httpx");

/// The QUIC/HTTP3 modules currently expose protocol codecs and fixtures, not
/// an authenticated transport. Public requests are rejected rather than sent
/// as plaintext pseudo-QUIC.
pub fn main() !void {
    var client = httpx.Client.initWithConfig(std.heap.page_allocator, .{
        .http3_enabled = true,
        .http2_enabled = false,
    });
    defer client.deinit();

    if (client.get("https://example.test/", .{ .version = .HTTP_3 })) |response| {
        var owned = response;
        defer owned.deinit();
        return error.UnexpectedHttp3Support;
    } else |err| {
        if (err != error.UnsupportedHttpVersion) return err;
        std.debug.print(
            "HTTP/3 client transport is unavailable until authenticated QUIC is implemented.\n",
            .{},
        );
    }
}
