# HTTP/3 Server Runtime Example

The public server deliberately rejects HTTP/3 until a real authenticated QUIC
transport is available.

```zig
var server = httpx.Server.initWithConfig(allocator, .{
    .http3_enabled = true,
});
defer server.deinit();

try std.testing.expectError(
    error.UnsupportedHttpVersion,
    server.listenInBackground(),
);
```

The low-level QUIC, HTTP/3 framing, and QPACK modules remain available as
experimental codec primitives. They do not provide TLS 1.3-in-QUIC,
authentication, packet/header protection, loss recovery, or congestion control.
