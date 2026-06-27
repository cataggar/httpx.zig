# SOCKS5h Proxy

SOCKS5h is the SOCKS5 proxy variant that keeps hostname resolution on the proxy side instead of the client side. In `httpx.zig`, you opt into that behavior by setting the proxy kind to `.socks5h`.

## Why Use SOCKS5h

- Avoids local DNS lookups for proxied requests.
- Works well when the proxy can resolve private or internal hostnames.
- Matches the `socks5h://` convention used by common HTTP tooling.

## Client Example

```zig
const httpx = @import("httpx");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = httpx.Client.initWithConfig(allocator, .{
        .proxy = .{
            .kind = .socks5h,
            .host = "127.0.0.1",
            .port = 1080,
        },
    });
    defer client.deinit();

    const response = try client.get("https://example.com", .{});
    defer response.deinit();
}
```

## Behavioral Notes

- `http` proxy mode keeps the standard forward-proxy behavior.
- TLS requests still use CONNECT tunnels when needed.
- `socks5h` sends the hostname to the proxy so the proxy performs DNS resolution.

## What to Verify

- The client connects through the SOCKS5h endpoint without resolving the target host locally.
- Requests to internal names or privacy-sensitive hostnames succeed when the proxy can resolve them.
- Existing HTTP proxy behavior remains unchanged for `.kind = .http`.
