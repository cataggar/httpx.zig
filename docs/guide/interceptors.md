# Interceptors

Interceptors are powerful hooks that allow you to safeguard or modify requests and responses globally.

Common use cases include:
- Adding authentication tokens to every request.
- Logging request/response details.
- Automating error handling or retry logic beyond the built-in policy.
- Transforming response data.

## Setup

Interceptors are defined using the `Interceptor` struct and added to the client.

```zig
pub const Interceptor = struct {
    request_fn: ?RequestInterceptor = null,
    response_fn: ?ResponseInterceptor = null,
    error_fn: ?ErrorInterceptor = null,
    retry_fn: ?RetryInterceptor = null,
    redirect_fn: ?RedirectInterceptor = null,
    context: ?*anyopaque = null,
};
```

Each callback receives an `AttemptContext` with a logical request ID,
one-based attempt number, redirect count, effective policy, and URL. Request
and response/error callbacks run for every actual transport attempt. Retry and
redirect callbacks run only when the client performs that action.

## Example: Auth Token Injector

This interceptor adds a Bearer token to every outgoing request.

```zig
fn addAuthToken(req: *httpx.Request, attempt: *const httpx.AttemptContext, ctx: ?*anyopaque) !void {
    _ = attempt;
    _ = ctx;
    // In a real app, you might cast ctx to a Config struct
    try req.headers.set("Authorization", "Bearer my-secret-token");
}

// Usage
var client = httpx.Client.init(allocator);
try client.addInterceptor(.{
    .request_fn = addAuthToken,
    // response_fn can be null
});
```

## Example: Response Logger

```zig
fn logResponse(res: *httpx.Response, attempt: *const httpx.AttemptContext, ctx: ?*anyopaque) !void {
    _ = ctx;
    std.debug.print("Attempt {d}, status: {d}\n", .{ attempt.attempt, res.status.code });
}

try client.addInterceptor(.{
    .response_fn = logResponse,
});
```

You can chain multiple interceptors. They are snapshotted and executed in
registration order without a client lock held. Callbacks may run concurrently
and reentrantly, so their borrowed context must outlive all in-flight requests.
