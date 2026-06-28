# Unix Domain Sockets Guide

`httpx.zig` supports same-machine Inter-Process Communication (IPC) via Unix domain sockets (AF_UNIX), allowing HTTP traffic to bypass network stack overhead for maximum performance.

## Overview

Unix domain sockets:
- Bypass network card layer, TCP headers, loopback routing, and socket timeouts.
- Provide lower latency and higher throughput than localhost TCP loopback.
- Are fully supported on Linux, macOS, and Windows 10+ (1803+).

## Client Configuration

Configure the client to connect directly to the local Unix socket file rather than a TCP port:

```zig
const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var client = httpx.Client.initWithConfig(allocator, httpx.ClientConfig.defaults()
        .withUnixSocket("httpx-ipc.sock")
    );
    defer client.deinit();

    // Requests are sent entirely over the Unix socket file
    var resp = try client.get("http://localhost/ipc-status", .{});
    defer resp.deinit();
}
```

## Server Configuration

Configure the server to bind to a local path rather than a network port:

```zig
const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var server = httpx.Server.initWithConfig(allocator, .{
        .unix_path = "httpx-ipc.sock",
    });
    defer server.deinit();

    try server.get("/ipc-status", struct {
        fn h(ctx: *httpx.Context) anyerror!httpx.Response {
            return ctx.text("Connected over AF_UNIX!");
        }
    }.h);

    try server.listen();
}
```
