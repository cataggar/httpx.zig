# Observability & Metrics Guide

`httpx.zig` includes a built-in observability tracker (`Metrics`), providing real-time request counts, status-code classifications, latency analysis, and success rate monitoring.

## Overview

Observability is crucial for health monitoring and debugging production servers. The metrics module automatically records statistics during route execution, letting you expose real-time metrics endpoints for dashboard collectors (like Prometheus).

## Using Metrics

### 1. Collect Metrics

Initialize the metrics registry and update metrics inside your handlers or custom middleware:

```zig
const std = @import("std");
const httpx = @import("httpx");

var metrics = httpx.Metrics.init();

fn myRouteHandler(ctx: *httpx.Context) anyerror!httpx.Response {
    metrics.recordRequest();
    const start_time = std.time.nanoTimestamp();
    
    // Execute logic...
    const response = ctx.text("Hello!");

    const duration = std.time.nanoTimestamp() - start_time;
    
    // Record response details
    metrics.recordResponse(response.status.code, response.body.len, @intCast(duration));
    
    return response;
}
```

### 2. Expose Metrics Endpoint

Expose a `/metrics` endpoint on the server returning a metrics snapshot:

```zig
fn metricsHandler(ctx: *httpx.Context) anyerror!httpx.Response {
    const snapshot = metrics.snapshot();
    
    return ctx.json(.{
        .total_requests = snapshot.total_requests,
        .success_rate = snapshot.successRate(),
        .avg_latency_ms = snapshot.avg_latency_ns / 1_000_000,
        .status_2xx = snapshot.responses_2xx,
        .status_4xx = snapshot.responses_4xx,
        .status_5xx = snapshot.responses_5xx,
    });
}
```

### 3. Custom/External Service Callbacks

To forward metrics events directly to external monitoring platforms (like Datadog, Prometheus pushgateway, or internal logging aggregators), register a custom callback:

```zig
const std = @import("std");
const httpx = @import("httpx");

fn customMetricsCallback(event: httpx.MetricsEvent) void {
    switch (event) {
        .request => std.debug.print("[Metrics] Outgoing request started\n", .{}),
        .response => |resp| std.debug.print("[Metrics] Received status {d} (latency: {d} ns)\n", .{ resp.status, resp.latency_ns }),
        .err => std.debug.print("[Metrics] Error encountered\n", .{}),
        else => {},
    }
}

// Initialize registry with callback integration
var metrics = httpx.Metrics.initWithCallback(customMetricsCallback);
```
