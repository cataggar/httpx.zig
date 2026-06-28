# Session Management Guide

`httpx.zig` includes a built-in session management module (`SessionStore`), providing secure, thread-safe, TTL-based session tracking for servers.

## Features

- **In-Memory Store**: Fast, secure session storage requiring no external database dependency.
- **TTL Eviction**: Automatically removes expired sessions based on customizable Time-to-Live settings.
- **Thread Safety**: Uses internal lock synchronization to support safe concurrent execution.
- **Cookie Helpers**: Built-in methods to generate session IDs and manage HTTP cookies.

## Usage

### 1. Initialize the Session Store

Configure and initialize the session store on server startup:

```zig
const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Initialize session store with 30-minute expiration
    var store = httpx.SessionStore.initWithConfig(allocator, .{
        .ttl_seconds = 1800,
        .cookie_name = "session_id",
    });
    defer store.deinit();
}
```

### 2. Set and Get Session Values

Retrieve or store user authentication data during route execution:

```zig
fn loginHandler(ctx: *httpx.Context, store: *httpx.SessionStore) anyerror!httpx.Response {
    // 1. Authenticate user credentials...
    const user_id = "user_12345";

    // 2. Create new session and generate cookie header
    const session_id = try store.create(user_id);
    var cookie_options = httpx.CookieOptions{
        .path = "/",
        .http_only = true,
        .secure = true,
    };
    
    // 3. Set the cookie header on response
    try ctx.setCookie(store.config.cookie_name, session_id, cookie_options);
    
    return ctx.json(.{ .ok = true, .message = "Login successful" });
}

fn profileHandler(ctx: *httpx.Context, store: *httpx.SessionStore) anyerror!httpx.Response {
    // 1. Read session cookie from request
    const cookie_val = ctx.cookie(store.config.cookie_name) orelse 
        return ctx.status(httpx.StatusCode.UNAUTHORIZED).text("Unauthorized");

    // 2. Resolve user ID from session
    if (store.get(cookie_val)) |session| {
        return ctx.json(.{ .user_id = session.user_id });
    }

    return ctx.status(httpx.StatusCode.UNAUTHORIZED).text("Session expired");
}
```

### 3. Cleanup and Expiration

The `SessionStore` can periodically clear out expired sessions to reclaim memory:

```zig
// Clean up all sessions that have exceeded their TTL
store.cleanup();
```
