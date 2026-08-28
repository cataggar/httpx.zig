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
concurrent multiplexing. GOAWAY marks a session draining and later requests
open another connection. A GOAWAY that arrives after a completed response may
be observed by the next lease; that request returns an error in embedding-owned
mode, while an enabled retry policy may replay its buffered body on a new
session.

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
