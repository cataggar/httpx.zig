# WebSockets Guide

`httpx.zig` supports RFC 6455 WebSockets, providing upgrade validation, handshake computation, and framing capabilities to establish full-duplex communication over a single TCP connection.

## How WebSockets Work

1. **Client Handshake Request**: The client sends a standard HTTP GET request with upgrade headers:
   - `Connection: Upgrade`
   - `Upgrade: websocket`
   - `Sec-WebSocket-Key: <base64-nonce>`
   - `Sec-WebSocket-Version: 13`
2. **Server Upgrade Response**: The server validates the upgrade and returns a `101 Switching Protocols` status code with the computed accept signature:
   - `Sec-WebSocket-Accept: <accept-signature>`
3. **Data Framing**: Communication switches to binary framing, sending text or binary data frames back and forth.

## Using WebSockets

### Server Upgrade Handling

You can intercept and upgrade incoming requests in a route handler by checking the WebSocket headers and computing the handshake key:

```zig
const std = @import("std");
const httpx = @import("httpx");

fn wsHandler(ctx: *httpx.Context) anyerror!httpx.Response {
    if (httpx.websocket.isWebSocketUpgrade(ctx.request)) {
        const client_key = ctx.header("Sec-WebSocket-Key").?;
        const accept_key = try httpx.websocket.computeHandshakeAcceptKey(ctx.allocator, client_key);
        defer ctx.allocator.free(accept_key);

        _ = try ctx.response.header("Upgrade", "websocket");
        _ = try ctx.response.header("Connection", "Upgrade");
        _ = try ctx.response.header("Sec-WebSocket-Accept", accept_key);
        
        // Return 101 Switching Protocols to upgrade
        return ctx.status(httpx.StatusCode.SWITCHING_PROTOCOLS).build();
    }
    
    return ctx.status(httpx.StatusCode.BAD_REQUEST).text("Not a websocket upgrade");
}
```

### Reading and Writing Frames

Use the framing helpers to parse incoming frame payloads or encode outbound frames:

```zig
// Create a text frame
var text_frame = try httpx.websocket.wsTextFrame(allocator, "Hello, world!");
defer allocator.free(text_frame);

// Send the frame over the upgraded connection handle
try conn.writeAll(text_frame);
```
