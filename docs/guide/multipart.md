# Multipart Form Data Guide

`httpx.zig` supports RFC 2046 Multipart Form Data, offering a flexible builder and parser for handling standard form fields and file attachments.

## Overview

Multipart requests are typically used when uploading files or posting complex fields. Each part has its own header section (such as `Content-Disposition` and `Content-Type`) and is separated by a unique boundary token string.

## Creating Multipart Requests (Client)

Use `MultipartBuilder` to construct form data payloads dynamically:

```zig
const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var client = httpx.Client.init(allocator);
    defer client.deinit();

    // 1. Initialize the builder
    var builder = httpx.MultipartBuilder.init(allocator);
    defer builder.deinit();

    // 2. Add text fields
    try builder.addField("username", "john_doe");
    try builder.addField("email", "john@example.com");

    // 3. Add file uploads (with mime type)
    try builder.addFile("profile_pic", "avatar.png", "image/png", "PNG_BINARY_DATA_HERE");

    // 4. Build the payload and content-type header
    const body = try builder.build();
    defer allocator.free(body);

    const content_type = try builder.contentTypeHeader();
    defer allocator.free(content_type);

    // 5. Send POST request
    var reqOpts = httpx.RequestOptions.defaults();
    try reqOpts.headers.set("Content-Type", content_type);
    reqOpts.body = body;

    var resp = try client.post("https://api.example.com/upload", reqOpts);
    defer resp.deinit();
}
```

## Parsing Multipart Payloads (Server)

Extract and parse file uploads or form fields on the server:

```zig
fn uploadHandler(ctx: *httpx.Context) anyerror!httpx.Response {
    const content_type = ctx.header("Content-Type") orelse 
        return ctx.status(httpx.StatusCode.BAD_REQUEST).text("Missing Content-Type");

    // 1. Extract boundary string from header
    const boundary = try httpx.extractMultipartBoundary(content_type);

    // 2. Parse the body using the boundary
    const body = ctx.request.body orelse "";
    var parts = try httpx.parseMultipart(ctx.allocator, body, boundary);
    defer {
        for (parts.items) |part| {
            ctx.allocator.free(part.name);
            if (part.filename) |f| ctx.allocator.free(f);
            if (part.content_type) |c| ctx.allocator.free(c);
            ctx.allocator.free(part.data);
        }
        parts.deinit();
    }

    // 3. Retrieve fields/files
    for (parts.items) |part| {
        if (part.filename) |filename| {
            std.debug.print("Received file: {s} ({d} bytes)\n", .{filename, part.data.len});
        } else {
            std.debug.print("Field: {s} = {s}\n", .{part.name, part.data});
        }
    }

    return ctx.text("Upload processed!");
}
```
