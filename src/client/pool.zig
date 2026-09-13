//! HTTP connection pool for httpx.zig.
//!
//! Pool entries are individually heap allocated. A checked-out lease therefore
//! remains stable even when the pointer array grows or idle entries are removed.

const std = @import("std");
const Allocator = std.mem.Allocator;

const Socket = @import("../net/socket.zig").Socket;
const TcpListener = @import("../net/socket.zig").TcpListener;
const address_mod = @import("../net/address.zig");
const dns_mod = @import("../net/dns.zig");
const types = @import("../core/types.zig");
const proxy_mod = @import("proxy.zig");
const common = @import("../data/common.zig");
const IoContext = @import("../io/context.zig").IoContext;
const TLSSession = @import("../tls/tls.zig").TLSSession;
const TLSConfig = @import("../tls/tls.zig").TLSConfig;
const h2stream = @import("../protocol/stream.zig");
const Proxy = types.Proxy;

pub const PoolError = error{
    PoolExhausted,
    PoolExhaustedForHost,
};

pub const PoolScheme = enum {
    plain,
    tls,
};

pub const PoolProtocol = enum {
    http1,
    http2,
};

/// Complete reuse identity for one transport route.
pub const PoolKey = struct {
    scheme: PoolScheme = .plain,
    host: []const u8,
    port: u16,
    proxy: ?Proxy = null,
    verify_tls: bool = true,
    protocol: PoolProtocol = .http1,
};

const OwnedPoolKey = struct {
    scheme: PoolScheme,
    host: []u8,
    port: u16,
    proxy_kind: ?types.ProxyKind = null,
    proxy_host: ?[]u8 = null,
    proxy_port: ?u16 = null,
    proxy_username: ?[]u8 = null,
    proxy_password: ?[]u8 = null,
    verify_tls: bool,
    protocol: PoolProtocol,

    fn init(allocator: Allocator, key: PoolKey) !OwnedPoolKey {
        const host = try allocator.dupe(u8, key.host);
        errdefer allocator.free(host);
        const proxy_host = if (key.proxy) |proxy|
            try allocator.dupe(u8, proxy.host)
        else
            null;
        errdefer if (proxy_host) |value| allocator.free(value);
        const proxy_username = if (key.proxy) |proxy|
            if (proxy.username) |value| try allocator.dupe(u8, value) else null
        else
            null;
        errdefer if (proxy_username) |value| allocator.free(value);
        const proxy_password = if (key.proxy) |proxy|
            if (proxy.password) |value| try allocator.dupe(u8, value) else null
        else
            null;
        return .{
            .scheme = key.scheme,
            .host = host,
            .port = key.port,
            .proxy_kind = if (key.proxy) |proxy| proxy.kind else null,
            .proxy_host = proxy_host,
            .proxy_port = if (key.proxy) |proxy| proxy.port else null,
            .proxy_username = proxy_username,
            .proxy_password = proxy_password,
            .verify_tls = key.verify_tls,
            .protocol = key.protocol,
        };
    }

    fn deinit(self: *OwnedPoolKey, allocator: Allocator) void {
        allocator.free(self.host);
        if (self.proxy_host) |host| allocator.free(host);
        if (self.proxy_username) |username| allocator.free(username);
        if (self.proxy_password) |password| allocator.free(password);
    }

    fn matches(self: *const OwnedPoolKey, key: PoolKey) bool {
        if (self.scheme != key.scheme or
            self.port != key.port or
            self.verify_tls != key.verify_tls or
            self.protocol != key.protocol or
            !std.mem.eql(u8, self.host, key.host))
        {
            return false;
        }
        if (key.proxy) |proxy| {
            const proxy_host = self.proxy_host orelse return false;
            return self.proxy_kind == proxy.kind and
                self.proxy_port == proxy.port and
                std.mem.eql(u8, proxy_host, proxy.host) and
                optionalEql(self.proxy_username, proxy.username) and
                optionalEql(self.proxy_password, proxy.password);
        }
        return self.proxy_host == null;
    }
};

fn optionalEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

pub const EntryState = enum {
    connecting,
    idle,
    leased,
    draining,
    closed,
};

/// Persistent state for sequential HTTP/2 session reuse.
///
/// A pool lease gives one caller exclusive ownership of this state. HTTP/2
/// multiplexing is intentionally not attempted by the client.
pub const H2SessionState = struct {
    stream_manager: h2stream.StreamManager,
    initialized: bool = false,
    received_initial_settings: bool = false,
    peer_max_frame_size: u32 = 16_384,
    draining: bool = false,
    poisoned: bool = false,
    reset_count: u64 = 0,

    pub fn init(allocator: Allocator) H2SessionState {
        return .{ .stream_manager = h2stream.StreamManager.init(allocator, true) };
    }

    pub fn deinit(self: *H2SessionState) void {
        self.stream_manager.deinit();
    }
};

const Entry = struct {
    key: OwnedPoolKey,
    socket: ?Socket = null,
    tls_session: ?TLSSession = null,
    h2_session: ?H2SessionState = null,
    state: EntryState = .connecting,
    generation: u64 = 0,
    lease_count: u32 = 0,
    created_at: i64,
    last_used: i64,
    requests_made: u32 = 0,

    fn isHealthy(self: *const Entry, max_idle_ms: i64, max_requests: u32) bool {
        if (self.state != .idle) return false;
        const socket = self.socket orelse return false;
        if (!socket.isValid() or self.requests_made >= max_requests) return false;
        return common.nowMillis() - self.last_used < max_idle_ms;
    }

    fn shouldEvict(self: *const Entry, idle_timeout_ms: i64, max_requests: u32) bool {
        if (self.lease_count != 0 or self.state == .connecting or self.state == .leased) return false;
        const socket = self.socket orelse return true;
        if (!socket.isValid() or self.requests_made >= max_requests) return true;
        return self.state == .draining or common.nowMillis() - self.last_used >= idle_timeout_ms;
    }
};

pub const LeaseDisposition = enum {
    reusable,
    broken,
    draining,
};

/// Exclusive ownership of one heap-stable pool entry.
pub const ConnectionLease = struct {
    pool: *ConnectionPool,
    entry: *Entry,
    generation: u64,
    released: bool = false,

    pub fn socket(self: *ConnectionLease) *Socket {
        std.debug.assert(!self.released);
        return &self.entry.socket.?;
    }

    pub fn tlsSession(self: *ConnectionLease) ?*TLSSession {
        std.debug.assert(!self.released);
        if (self.entry.tls_session) |*session| return session;
        return null;
    }

    /// Initializes TLS in stable entry storage and returns the attached session.
    pub fn initializeTls(self: *ConnectionLease, config: TLSConfig) *TLSSession {
        std.debug.assert(!self.released);
        std.debug.assert(self.entry.tls_session == null);
        self.entry.tls_session = TLSSession.init(config);
        self.entry.tls_session.?.attachSocket(&self.entry.socket.?);
        return &self.entry.tls_session.?;
    }

    pub fn replaceSocket(self: *ConnectionLease, replacement: Socket) void {
        std.debug.assert(!self.released);
        if (self.entry.socket) |*old_socket| old_socket.close();
        self.entry.socket = replacement;
        if (self.entry.tls_session) |*session| {
            session.attachSocket(&self.entry.socket.?);
        }
    }

    pub fn h2Session(self: *ConnectionLease) *H2SessionState {
        std.debug.assert(!self.released);
        if (self.entry.h2_session == null) {
            self.entry.h2_session = H2SessionState.init(self.pool.allocator);
        }
        return &self.entry.h2_session.?;
    }

    pub fn isFresh(self: *const ConnectionLease) bool {
        return self.entry.requests_made == 0 and
            self.entry.tls_session == null and
            self.entry.h2_session == null;
    }

    pub fn requestCount(self: *const ConnectionLease) u32 {
        return self.entry.requests_made;
    }

    pub fn rekeyProtocol(self: *ConnectionLease, protocol: PoolProtocol) !void {
        if (self.released) return error.LeaseAlreadyReleased;
        try self.pool.rekeyProtocol(self.entry, self.generation, protocol);
    }

    /// Stable identity useful for diagnostics and regression tests.
    pub fn entryAddress(self: *const ConnectionLease) usize {
        return @intFromPtr(self.entry);
    }

    pub fn release(self: *ConnectionLease, disposition: LeaseDisposition) !void {
        if (self.released) return error.LeaseAlreadyReleased;
        self.released = true;
        try self.pool.releaseLease(self.entry, self.generation, disposition);
    }
};

/// Connection pool configuration.
pub const PoolConfig = struct {
    max_connections: u32 = 20,
    max_per_host: u32 = 5,
    idle_timeout_ms: i64 = 60_000,
    max_requests_per_connection: u32 = 1000,
    health_check_interval_ms: i64 = 30_000,
    connect_timeout_ms: u64 = 30_000,
    dns_resolver: ?*dns_mod.DNSResolver = null,
};

/// Snapshot statistics for the connection pool.
pub const PoolStats = struct {
    total: usize,
    active: usize,
    idle: usize,
};

/// Thread-safe pool of stable entries.
pub const ConnectionPool = struct {
    allocator: Allocator,
    config: PoolConfig,
    entries: std.ArrayList(*Entry) = .empty,
    lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    const Self = @This();

    fn acquireLock(self: *Self) void {
        while (self.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.Thread.yield() catch {};
        }
    }

    fn acquireLockWithContext(self: *Self, context: *const IoContext) !void {
        while (self.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            try context.waitForMs(1);
        }
        context.check() catch |err| {
            self.releaseLock();
            return err;
        };
    }

    fn releaseLock(self: *Self) void {
        self.lock.store(0, .release);
    }

    pub fn init(allocator: Allocator) Self {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: Allocator, config: PoolConfig) Self {
        return .{ .allocator = allocator, .config = config };
    }

    /// Exclusive shutdown. No leases may remain outstanding.
    pub fn deinit(self: *Self) void {
        self.acquireLock();
        const entries = self.entries;
        self.entries = .empty;
        self.releaseLock();

        for (entries.items) |entry| {
            std.debug.assert(entry.lease_count == 0);
            self.destroyEntry(entry);
        }
        var owned_entries = entries;
        owned_entries.deinit(self.allocator);
    }

    /// Compatibility helper for a plain HTTP/1.1 route.
    pub fn getConnection(self: *Self, host: []const u8, port: u16, proxy: ?Proxy, connect_timeout_ms: u64) !ConnectionLease {
        const context = IoContext.init(.{});
        return self.getConnectionWithContext(host, port, proxy, connect_timeout_ms, &context);
    }

    /// Compatibility helper for a plain HTTP/1.1 route.
    pub fn getConnectionWithContext(
        self: *Self,
        host: []const u8,
        port: u16,
        proxy: ?Proxy,
        connect_timeout_ms: u64,
        context: *const IoContext,
    ) !ConnectionLease {
        return self.getLeaseWithContext(.{
            .host = host,
            .port = port,
            .proxy = proxy,
        }, connect_timeout_ms, context);
    }

    pub fn getLeaseWithContext(
        self: *Self,
        key: PoolKey,
        connect_timeout_ms: u64,
        context: *const IoContext,
    ) !ConnectionLease {
        try self.acquireLockWithContext(context);

        for (self.entries.items) |entry| {
            if (entry.key.matches(key) and entry.isHealthy(
                self.config.idle_timeout_ms,
                self.config.max_requests_per_connection,
            )) {
                const lease = self.checkoutLocked(entry);
                self.releaseLock();
                return lease;
            }
        }

        if (self.entries.items.len >= self.config.max_connections) {
            self.releaseLock();
            return PoolError.PoolExhausted;
        }

        var host_count: u32 = 0;
        for (self.entries.items) |entry| {
            if (entry.key.port == key.port and std.mem.eql(u8, entry.key.host, key.host)) {
                host_count += 1;
            }
        }
        if (host_count >= self.config.max_per_host) {
            self.releaseLock();
            return PoolError.PoolExhaustedForHost;
        }

        const owned_key = OwnedPoolKey.init(self.allocator, key) catch |err| {
            self.releaseLock();
            return err;
        };
        const entry = self.allocator.create(Entry) catch |err| {
            var mutable_key = owned_key;
            mutable_key.deinit(self.allocator);
            self.releaseLock();
            return err;
        };
        const now = common.nowMillis();
        entry.* = .{
            .key = owned_key,
            .state = .connecting,
            .lease_count = 1,
            .generation = 1,
            .created_at = now,
            .last_used = now,
        };
        self.entries.append(self.allocator, entry) catch |err| {
            self.destroyEntry(entry);
            self.releaseLock();
            return err;
        };
        self.releaseLock();

        self.connectEntry(entry, key, connect_timeout_ms, context) catch |err| {
            self.acquireLock();
            _ = self.unlinkEntryLocked(entry);
            self.releaseLock();
            entry.lease_count = 0;
            self.destroyEntry(entry);
            return err;
        };

        self.acquireLock();
        entry.state = .leased;
        self.releaseLock();
        return .{ .pool = self, .entry = entry, .generation = entry.generation };
    }

    pub fn tryGetLeaseWithContext(
        self: *Self,
        key: PoolKey,
        context: *const IoContext,
    ) !?ConnectionLease {
        try self.acquireLockWithContext(context);
        defer self.releaseLock();
        for (self.entries.items) |entry| {
            if (entry.key.matches(key) and entry.isHealthy(
                self.config.idle_timeout_ms,
                self.config.max_requests_per_connection,
            )) {
                return self.checkoutLocked(entry);
            }
        }
        return null;
    }

    fn checkoutLocked(self: *Self, entry: *Entry) ConnectionLease {
        entry.state = .leased;
        entry.lease_count = 1;
        entry.generation +%= 1;
        entry.last_used = common.nowMillis();
        return .{ .pool = self, .entry = entry, .generation = entry.generation };
    }

    fn rekeyProtocol(
        self: *Self,
        entry: *Entry,
        generation: u64,
        protocol: PoolProtocol,
    ) !void {
        self.acquireLock();
        defer self.releaseLock();
        if (entry.generation != generation or entry.state != .leased or entry.lease_count != 1) {
            return error.StaleLease;
        }
        entry.key.protocol = protocol;
    }

    fn connectEntry(
        self: *Self,
        entry: *Entry,
        key: PoolKey,
        connect_timeout_ms: u64,
        context: *const IoContext,
    ) !void {
        try context.check();
        const connect_host = if (key.proxy) |proxy| proxy.host else key.host;
        const connect_port = if (key.proxy) |proxy| proxy.port else key.port;
        const addr = if (self.config.dns_resolver) |resolver| blk: {
            var result = try resolver.resolveWithContext(connect_host, .{ .port = connect_port }, context);
            defer result.deinit();
            if (result.addresses.len == 0) return error.DNSResolutionFailed;
            break :blk result.addresses[0];
        } else blk: {
            break :blk try address_mod.resolveWithContext(connect_host, connect_port, context);
        };

        var socket = try Socket.createForAddress(addr);
        errdefer socket.close();
        try socket.connectWithContext(addr, connect_timeout_ms, context);
        try socket.setNoDelay(true);

        if (key.proxy) |proxy| {
            if (proxy.kind == .socks5h) {
                try context.check();
                try proxy_mod.establishSocks5hTunnelWithContext(
                    &socket,
                    key.host,
                    key.port,
                    proxy,
                    context,
                );
            }
        }

        entry.socket = socket;
    }

    fn releaseLease(
        self: *Self,
        entry: *Entry,
        generation: u64,
        disposition: LeaseDisposition,
    ) !void {
        self.acquireLock();
        if (entry.generation != generation or entry.state != .leased or entry.lease_count != 1) {
            self.releaseLock();
            return error.StaleLease;
        }

        entry.lease_count = 0;
        entry.requests_made +%= 1;
        entry.last_used = common.nowMillis();

        const can_reuse = disposition == .reusable and
            entry.socket != null and
            entry.socket.?.isValid() and
            entry.requests_made < self.config.max_requests_per_connection and
            !(if (entry.tls_session) |tls_session| tls_session.write_poisoned else false) and
            !(if (entry.h2_session) |h2| h2.draining or h2.poisoned else false);

        if (can_reuse) {
            entry.state = .idle;
            self.releaseLock();
            return;
        }

        entry.state = if (disposition == .draining) .draining else .closed;
        _ = self.unlinkEntryLocked(entry);
        self.releaseLock();
        self.destroyEntry(entry);
    }

    fn unlinkEntryLocked(self: *Self, target: *Entry) bool {
        for (self.entries.items, 0..) |entry, index| {
            if (entry == target) {
                _ = self.entries.orderedRemove(index);
                return true;
            }
        }
        return false;
    }

    fn destroyEntry(self: *Self, entry: *Entry) void {
        if (entry.h2_session) |*h2| h2.deinit();
        if (entry.tls_session) |*session| session.deinit();
        if (entry.socket) |*socket| socket.close();
        entry.key.deinit(self.allocator);
        self.allocator.destroy(entry);
    }

    /// Removes only zero-lease entries. Checked-out entries remain stable.
    pub fn cleanup(self: *Self) void {
        while (true) {
            self.acquireLock();
            var victim: ?*Entry = null;
            for (self.entries.items) |entry| {
                if (entry.shouldEvict(
                    self.config.idle_timeout_ms,
                    self.config.max_requests_per_connection,
                )) {
                    victim = entry;
                    _ = self.unlinkEntryLocked(entry);
                    break;
                }
            }
            self.releaseLock();
            const entry = victim orelse return;
            self.destroyEntry(entry);
        }
    }

    fn statsLocked(self: *Self) PoolStats {
        var active: usize = 0;
        var idle: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.lease_count > 0 or entry.state == .connecting) active += 1;
            if (entry.state == .idle) idle += 1;
        }
        return .{ .total = self.entries.items.len, .active = active, .idle = idle };
    }

    pub fn totalCount(self: *Self) usize {
        self.acquireLock();
        defer self.releaseLock();
        return self.entries.items.len;
    }

    pub fn activeCount(self: *Self) usize {
        return self.stats().active;
    }

    pub fn idleCount(self: *Self) usize {
        return self.stats().idle;
    }

    pub fn hostConnectionCount(self: *Self, host: []const u8, port: u16) usize {
        self.acquireLock();
        defer self.releaseLock();
        var count: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.key.port == port and std.mem.eql(u8, entry.key.host, host)) count += 1;
        }
        return count;
    }

    pub fn h2NextClientStreamId(self: *Self, host: []const u8, port: u16) ?u31 {
        self.acquireLock();
        defer self.releaseLock();
        for (self.entries.items) |entry| {
            if (entry.key.port == port and std.mem.eql(u8, entry.key.host, host)) {
                if (entry.h2_session) |*session| {
                    return session.stream_manager.next_client_stream_id;
                }
            }
        }
        return null;
    }

    pub fn stats(self: *Self) PoolStats {
        self.acquireLock();
        defer self.releaseLock();
        return self.statsLocked();
    }
};

test "ConnectionPool initialization" {
    var pool = ConnectionPool.init(std.testing.allocator);
    defer pool.deinit();
    try std.testing.expectEqual(@as(usize, 0), pool.totalCount());
}

test "ConnectionPool config" {
    var pool = ConnectionPool.initWithConfig(std.testing.allocator, .{
        .max_connections = 50,
        .max_per_host = 10,
    });
    defer pool.deinit();
    try std.testing.expectEqual(@as(u32, 50), pool.config.max_connections);
    try std.testing.expectEqual(@as(u32, 10), pool.config.max_per_host);
}

test "ConnectionPool contextual acquisition observes cancellation during lock wait" {
    var pool = ConnectionPool.init(std.testing.allocator);
    defer pool.deinit();

    pool.lock.store(1, .release);
    defer pool.lock.store(0, .release);
    var token = types.CancellationToken.init();
    token.cancel();
    const context = IoContext.init(.{ .external_cancel = &token });

    try std.testing.expectError(
        error.Cancelled,
        pool.getConnectionWithContext("127.0.0.1", 80, null, 1, &context),
    );
}

test "ConnectionPool stats helpers" {
    var pool = ConnectionPool.init(std.testing.allocator);
    defer pool.deinit();
    const stats = pool.stats();
    try std.testing.expectEqual(@as(usize, 0), stats.total);
    try std.testing.expectEqual(@as(usize, 0), stats.active);
    try std.testing.expectEqual(@as(usize, 0), stats.idle);
}

test "ConnectionPool growth keeps checked-out lease addresses stable" {
    const connection_count = 24;
    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const address = try listener.getLocalAddress();

    const AcceptServer = struct {
        listener: *TcpListener,
        release: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            var sockets: [connection_count]Socket = undefined;
            var accepted_count: usize = 0;
            defer {
                for (sockets[0..accepted_count]) |*socket| socket.close();
            }

            while (accepted_count < connection_count) : (accepted_count += 1) {
                const accepted = self.listener.accept() catch |err| {
                    self.failure = err;
                    return;
                };
                sockets[accepted_count] = accepted.socket;
            }
            while (!self.release.load(.acquire)) {
                std.Thread.yield() catch {};
            }
        }
    };

    var server = AcceptServer{ .listener = &listener };
    const thread = try std.Thread.spawn(.{}, AcceptServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        server.release.store(true, .release);
        thread.join();
    };

    var pool = ConnectionPool.initWithConfig(std.testing.allocator, .{
        .max_connections = connection_count,
        .max_per_host = connection_count,
    });
    defer pool.deinit();

    var leases: [connection_count]ConnectionLease = undefined;
    const context = IoContext.init(.{});
    for (&leases) |*lease| {
        lease.* = try pool.getLeaseWithContext(.{
            .host = "127.0.0.1",
            .port = address.getPort(),
        }, 5_000, &context);
    }

    const first_address = leases[0].entryAddress();
    try std.testing.expectEqual(first_address, leases[0].entryAddress());
    pool.cleanup();
    try std.testing.expectEqual(@as(usize, connection_count), pool.stats().active);
    try std.testing.expectEqual(first_address, leases[0].entryAddress());

    for (&leases) |*lease| try lease.release(.reusable);
    try std.testing.expectEqual(@as(usize, connection_count), pool.stats().idle);
    try std.testing.expectError(error.LeaseAlreadyReleased, leases[0].release(.reusable));

    server.release.store(true, .release);
    thread.join();
    joined = true;
    try std.testing.expect(server.failure == null);
}

test "pool key allocation is failure safe" {
    const Case = struct {
        fn run(allocator: Allocator) !void {
            var key = try OwnedPoolKey.init(allocator, .{
                .scheme = .tls,
                .host = "example.test",
                .port = 443,
                .proxy = .{
                    .kind = .http,
                    .host = "proxy.test",
                    .port = 8080,
                    .username = "user",
                    .password = "password",
                },
                .verify_tls = true,
                .protocol = .http2,
            });
            defer key.deinit(allocator);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Case.run, .{});
}
