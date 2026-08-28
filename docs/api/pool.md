# Connection Pool API

`ConnectionPool` owns heap-stable TCP/TLS/HTTP2 entries. The pointer array may
grow or compact without moving a checked-out transport. Each caller receives an
exclusive `ConnectionLease`.

## Initialization

```zig
var pool = httpx.ConnectionPool.initWithConfig(allocator, .{
    .max_connections = 100,
    .max_per_host = 10,
    .idle_timeout_ms = 30_000,
    .max_requests_per_connection = 500,
});
defer pool.deinit();
```

## Acquisition

The compatibility helpers acquire a plain HTTP/1.1 route:

```zig
var lease = try pool.getConnection("api.example.com", 80, null, 5_000);
defer lease.release(.broken) catch {};
```

Embedding transports should provide the complete reuse identity:

```zig
var lease = try pool.getLeaseWithContext(.{
    .scheme = .tls,
    .host = "api.example.com",
    .port = 443,
    .verify_tls = true,
    .protocol = .http2,
}, 5_000, &io_context);
```

The key includes scheme, target host/port, proxy route, TLS verification mode,
and requested HTTP protocol. Strings are deep-owned by the pool.

## Lease lifecycle

```zig
const socket = lease.socket();
// Perform one complete request/response exchange.
try lease.release(.reusable);
```

`LeaseDisposition` is:

- `.reusable` — the response was fully framed and the peer permits reuse.
- `.draining` — retire after the current exchange (for example,
  `Connection: close` or HTTP/2 GOAWAY).
- `.broken` — protocol, parse, TLS, or I/O failure.

A lease may be released exactly once. Duplicate releases return
`error.LeaseAlreadyReleased`; stale generations return `error.StaleLease`.
Cleanup removes only zero-lease entries.

TLS is initialized in stable entry storage with `lease.initializeTls(config)`.
Sequential HTTP/2 state is returned by `lease.h2Session()` and persists HPACK,
SETTINGS, flow-control windows, and monotonically increasing client stream IDs.
The high-level client does not concurrently multiplex a leased session.
Partial SETTINGS and WINDOW_UPDATE frames modify retained state. GOAWAY drains
the entry, but an active stream permitted by `last_stream_id` is read through
END_STREAM.

An opportunistic HTTP/2 TLS connection that negotiates HTTP/1.1 can be re-keyed
to `.http1` while exclusively leased. Future opportunistic requests first
reuse that published HTTP/1.1 entry.

## Statistics

| Method | Returns | Description |
|--------|---------|-------------|
| `activeCount()` | `usize` | Connecting or leased entries |
| `totalCount()` | `usize` | All tracked entries |
| `idleCount()` | `usize` | Entries available for reuse |
| `hostConnectionCount(host, port)` | `usize` | Entries for one target |
| `stats()` | `PoolStats` | Total/active/idle snapshot |
| `cleanup()` | `void` | Evict idle, exhausted, broken, or draining entries |

`deinit()` is exclusive and requires every lease to have been released.

## Pool errors

```zig
pub const PoolError = error{
    PoolExhausted,
    PoolExhaustedForHost,
};
```

## See Also

- [Client API](client.md)
- [Pooling Guide](/guide/pooling)
