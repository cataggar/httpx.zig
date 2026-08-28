# Connection Pooling & Concurrency

`httpx.zig` handles connection concurrency at two levels: 
1. **Internal Connection Pooling**: Reusing socket connections for efficiency.
2. **Parallel Request Execution**: Running multiple requests essentially at the same time.

## Connection Pooling

The `Client` automatically manages a pool of TCP and TLS connections. Each
entry is heap-stable and checked out through an exclusive lease, so growing or
cleaning the pool cannot invalidate an in-use handle. HTTPS keeps its
`TLSSession` attached to the stable socket entry across requests.

HTTP/2 keeps HPACK, SETTINGS, flow-control, and stream-id state with the pooled
session. Reuse is deliberately sequential (stream IDs 1, 3, 5, ...), not
concurrent multiplexing. Partial SETTINGS and connection/stream WINDOW_UPDATE
frames update the retained session state. GOAWAY marks a session draining; an
active stream permitted by `last_stream_id` continues until END_STREAM, while
a disallowed stream fails rather than returning a partial body.

When HTTP/2 is enabled opportunistically and ALPN selects HTTP/1.1, the
negotiated TLS session is safely re-keyed and reused as HTTP/1.1 rather than
failing the request.

### Configuration

You can configure the pool size and behavior via `ClientConfig`:

```zig
const config = httpx.ClientConfig{
    .keep_alive = true,
    .pool_max_connections = 50,  // Total connections in pool
    .pool_max_per_host = 10,     // Max connections to a single host
};
```

This acts mostly transparently to the user.

For parallel request execution (all, race, any) and task execution, see the [Concurrency](/guide/concurrency) guide.
