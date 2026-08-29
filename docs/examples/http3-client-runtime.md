# HTTP/3 Client Runtime Example

The public client deliberately rejects HTTP/3 until a real authenticated QUIC
transport is available.

```zig
var client = httpx.Client.initWithConfig(allocator, .{
    .http3_enabled = true,
});
defer client.deinit();

try std.testing.expectError(
    error.UnsupportedHttpVersion,
    client.get("https://example.com/", .{}),
);
```

The low-level QUIC, HTTP/3 framing, and QPACK modules remain available as
experimental codec primitives only.
