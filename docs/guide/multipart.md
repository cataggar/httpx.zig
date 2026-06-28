# Multipart Form Data Guide

`httpx.zig` provides RFC 2046 multipart/form-data support for building and parsing form submissions with file attachments.

## What Multipart Is

Multipart/form-data is the encoding used when HTML forms contain file inputs, or when an HTTP client needs to send both text fields and binary file data in the same request. Each part has its own headers (`Content-Disposition`, `Content-Type`) and is separated by a boundary string.

A multipart body looks like:

```
--boundary123
Content-Disposition: form-data; name="username"

alice
--boundary123
Content-Disposition: form-data; name="avatar"; filename="photo.png"
Content-Type: image/png

<binary PNG data>
--boundary123--
```

## Building Multipart Bodies

Use `MultipartBuilder` to construct the body incrementally:

```zig
const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var builder = httpx.MultipartBuilder.init(allocator, "boundary-abc123");
    defer builder.deinit();

    // Add text fields
    try builder.addField("username", "alice");
    try builder.addField("email", "alice@example.com");

    // Add a file upload
    const png_data = @embedFile("avatar.png");
    try builder.addFile("avatar", "photo.png", "image/png", png_data);

    // Finalize — caller owns the result
    const body = try builder.build();
    defer allocator.free(body);

    // Get the Content-Type header value with boundary
    const content_type = try builder.contentType();
    defer allocator.free(content_type);
    // content_type = "multipart/form-data; boundary=boundary-abc123"

    std.debug.print("body size: {d} bytes\n", .{body.len});
}
```

### `MultipartBuilder` API

| Method | Description |
|--------|-------------|
| `init(allocator, boundary)` | Create builder with a boundary string |
| `addField(name, value)` | Append a text form field |
| `addFile(name, filename, content_type, data)` | Append a file upload part |
| `build()` | Finalize and return the complete body (caller owns) |
| `contentType()` | Return the `Content-Type` header value (caller owns) |
| `deinit()` | Release builder resources |

The boundary must not contain `--` and should not exceed 70 characters (RFC 2046).

## Parsing Multipart Bodies

### Extracting the Boundary

Use `extractMultipartBoundary` (also exported as `httpx.extractMultipartBoundary`) to get the boundary string from a `Content-Type` header:

```zig
const content_type = "multipart/form-data; boundary=----WebKitFormBoundary";
const boundary = httpx.extractMultipartBoundary(content_type) orelse {
    return error.MissingBoundary;
};
// boundary = "----WebKitFormBoundary"
```

Returns `null` if no boundary parameter is present. Handles both quoted (`boundary="abc"`) and unquoted (`boundary=abc`) forms.

### Parsing Parts

```zig
const boundary = httpx.extractMultipartBoundary(content_type).?;
var result = try httpx.parseMultipart(allocator, body, boundary);
defer result.deinit();

for (result.parts) |part| {
    if (part.filename) |filename| {
        std.debug.print("file: {s} ({d} bytes, type={s})\n", .{
            filename, part.data.len, part.content_type,
        });
    } else {
        std.debug.print("field: {s} = {s}\n", .{ part.name, part.data });
    }
}
```

### `Part` fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `[]const u8` | Form field name from `Content-Disposition` |
| `filename` | `?[]const u8` | Original filename for file uploads, or null |
| `content_type` | `[]const u8` | Part content type (defaults to `"text/plain"`) |
| `data` | `[]const u8` | Raw bytes of the part body |
| `headers` | `[]const [2][]const u8` | All raw header pairs for this part |

`ParsedParts` has a `deinit()` method that frees all allocated memory. The `data` slice points into the internal raw buffer, so it is valid until `deinit()` is called.

## Integration with HTTP Requests

When sending a multipart request with the httpx client:

```zig
var builder = httpx.MultipartBuilder.init(allocator, "myBoundary");
defer builder.deinit();
try builder.addField("name", "alice");

const body = try builder.build();
defer allocator.free(body);
const ct = try builder.contentType();
defer allocator.free(ct);

var opts = httpx.RequestOptions.defaults();
opts.body = body;
try opts.withHeaders(&.{.{ "Content-Type", ct }});

var resp = try client.post("https://example.com/upload", opts);
defer resp.deinit();
```

## Full Server-Side Example

```zig
const std = @import("std");
const httpx = @import("httpx");

fn uploadHandler(ctx: *httpx.Context) anyerror!httpx.Response {
    const ct = ctx.request.headers.get("Content-Type") orelse
        return ctx.status(400).text("Missing Content-Type");

    const boundary = httpx.extractMultipartBoundary(ct) orelse
        return ctx.status(400).text("Missing boundary");

    const body = ctx.request.body orelse "";
    var result = try httpx.parseMultipart(ctx.allocator, body, boundary);
    defer result.deinit();

    for (result.parts) |part| {
        if (part.filename) |name| {
            std.debug.print("uploaded: {s} ({d} bytes)\n", .{ name, part.data.len });
        } else {
            std.debug.print("field {s}: {s}\n", .{ part.name, part.data });
        }
    }

    return ctx.json(.{ .ok = true, .parts = result.parts.len });
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = httpx.Server.init(allocator);
    defer server.deinit();

    try server.post("/upload", uploadHandler);
    try server.listen();
}
```
