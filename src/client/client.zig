//! HTTP Client Implementation for httpx.zig
//!
//! HTTP/1.1, HTTP/2, and HTTP/3 client runtime support.
//!
//! Notes:
//! - HTTP/2 runtime is supported with direct frame exchange.
//! - HTTP/3 runtime uses UDP + QUIC/HTTP3/QPACK primitives for local/integration
//!   endpoints. Full TLS-in-QUIC interoperability is still evolving.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const types = @import("../core/types.zig");
const meta = @import("../core/meta.zig");
const Headers = @import("../core/headers.zig").Headers;
const HeaderName = @import("../core/headers.zig").HeaderName;
const Uri = @import("../core/uri.zig").Uri;
const Request = @import("../core/request.zig").Request;
const Response = @import("../core/response.zig").Response;
const Status = @import("../core/status.zig").Status;
const Socket = @import("../net/socket.zig").Socket;
const TcpListener = @import("../net/socket.zig").TcpListener;
const UdpSocket = @import("../net/socket.zig").UdpSocket;
const SocketIoReader = @import("../net/socket.zig").SocketIoReader;
const SocketIoWriter = @import("../net/socket.zig").SocketIoWriter;
const address_mod = @import("../net/address.zig");
const http = @import("../protocol/http.zig");
const hpack = @import("../protocol/hpack.zig");
const h2stream = @import("../protocol/stream.zig");
const qpack = @import("../protocol/qpack.zig");
const quic = @import("../protocol/quic.zig");
const Parser = @import("../protocol/parser.zig").Parser;
const tls_mod = @import("../tls/tls.zig");
const TLSConfig = tls_mod.TLSConfig;
const TLSSession = tls_mod.TLSSession;
const TLSConnection = tls_mod.Connection;
const pool_mod = @import("pool.zig");
const ConnectionPool = pool_mod.ConnectionPool;
const ConnectionLease = pool_mod.ConnectionLease;
const proxy_mod = @import("proxy.zig");
const PoolStats = @import("pool.zig").PoolStats;
const common = @import("../data/common.zig");
const list_writer = @import("../io/list_writer.zig");
const compression_util = @import("../compress/compression.zig");
const io_util = @import("../io/any_io.zig");
const io_context = @import("../io/context.zig");
const IoContext = io_context.IoContext;
const Deadline = io_context.Deadline;
const Metrics = @import("../io/metrics.zig").Metrics;
const dns_mod = @import("../net/dns.zig");
const server_mod = @import("../server/server.zig");
const LogFn = server_mod.LogFn;

const defaultIo = io_util.defaultIo;

const RequestTimeouts = struct {
    connect_ms: u64,
    read_ms: u64,
    write_ms: u64,
    request_ms: u64,
};

/// HTTP client configuration.
pub const ClientConfig = struct {
    base_url: ?[]const u8 = null,
    timeouts: types.Timeouts = .{},
    policy: types.ClientPolicy = .{},
    default_headers: ?[]const [2][]const u8 = null,
    user_agent: []const u8 = meta.default_user_agent,
    max_response_size: usize = 100 * 1024 * 1024,
    max_request_size: usize = 10 * 1024 * 1024,
    verify_ssl: bool = true,
    http2_enabled: bool = false,
    http3_enabled: bool = false,
    allow_push: bool = true,
    http2_settings: types.HTTP2Settings = .{},
    http3_settings: types.HTTP3Settings = .{},
    keep_alive: bool = true,
    pool_max_connections: u32 = 20,
    pool_max_per_host: u32 = 5,
    proxy: ?types.Proxy = null,
    unix_socket_path: ?[]const u8 = null,
    log_fn: ?LogFn = null,
    log_level: server_mod.LogLevel = .info,
    metrics: ?*Metrics = null,
    /// Maximum number of cookies in the jar. 0 = unlimited.
    max_cookies: u32 = 1000,
    /// Maximum size in bytes of a single cookie name+value. 0 = unlimited.
    max_cookie_size: usize = 4096,
    /// Optional DNS resolver for hostname resolution. When set, the client uses
    /// this resolver (with its cache and deduplication) instead of the system resolver.
    dns_resolver: ?*dns_mod.DNSResolver = null,
    /// Compression options for request body compression. Null disables compression.
    request_compression: ?compression_util.CompressOptions = null,

    /// Returns default client configuration.
    pub fn defaults() ClientConfig {
        return .{};
    }

    /// Returns default configuration with a base URL.
    pub fn forBaseUrl(base_url: []const u8) ClientConfig {
        return .{ .base_url = base_url };
    }

    /// Returns a copy with a proxy configured.
    pub fn withProxy(self: ClientConfig, proxy: ?types.Proxy) ClientConfig {
        var out = self;
        out.proxy = proxy;
        return out;
    }

    /// Returns a copy with a new base URL.
    pub fn withBaseUrl(self: ClientConfig, base_url: ?[]const u8) ClientConfig {
        var out = self;
        out.base_url = base_url;
        return out;
    }

    /// Returns a copy with new timeout settings.
    pub fn withTimeouts(self: ClientConfig, timeouts: types.Timeouts) ClientConfig {
        var out = self;
        out.timeouts = timeouts;
        return out;
    }

    /// Returns a copy with all automatic client behavior configured.
    pub fn withPolicy(self: ClientConfig, policy: types.ClientPolicy) ClientConfig {
        var out = self;
        out.policy = policy;
        return out;
    }

    /// Compatibility helper that enables retries with the supplied policy.
    pub fn withRetryPolicy(self: ClientConfig, retry_policy: types.RetryPolicy) ClientConfig {
        var out = self;
        out.policy.retry = .{ .policy = retry_policy };
        return out;
    }

    /// Compatibility helper that enables redirects with the supplied policy.
    pub fn withRedirectPolicy(self: ClientConfig, redirect_policy: types.RedirectPolicy) ClientConfig {
        var out = self;
        out.policy.redirect = .{ .policy = redirect_policy };
        return out;
    }

    /// Returns a copy with default request headers applied to every request.
    pub fn withDefaultHeaders(self: ClientConfig, headers: ?[]const [2][]const u8) ClientConfig {
        var out = self;
        out.default_headers = headers;
        return out;
    }

    /// Returns a copy with a custom User-Agent.
    pub fn withUserAgent(self: ClientConfig, user_agent: []const u8) ClientConfig {
        var out = self;
        out.user_agent = user_agent;
        return out;
    }

    /// Compatibility helper for the former client-level redirect flag.
    /// Enabling redirects preserves the configured redirect policy when present,
    /// or installs the managed default after a previously disabled policy.
    pub fn withFollowRedirects(self: ClientConfig, follow_redirects: bool) ClientConfig {
        var out = self;
        if (follow_redirects) {
            out.policy.redirect = switch (out.policy.redirect) {
                .disabled => .{ .policy = .{} },
                .policy => |policy| .{ .policy = policy },
            };
        } else {
            out.policy.redirect = .disabled;
        }
        return out;
    }

    /// Returns a copy with a Unix domain socket path configured.
    pub fn withUnixSocket(self: ClientConfig, path: ?[]const u8) ClientConfig {
        var out = self;
        out.unix_socket_path = path;
        return out;
    }

    pub fn withLogFn(self: ClientConfig, log_fn: LogFn) ClientConfig {
        var config = self;
        config.log_fn = log_fn;
        return config;
    }

    /// Returns a copy with protocol runtime toggles.
    pub fn withProtocols(self: ClientConfig, http2_enabled: bool, http3_enabled: bool) ClientConfig {
        var out = self;
        out.http2_enabled = http2_enabled;
        out.http3_enabled = http3_enabled;
        return out;
    }

    /// Returns a copy with HTTP/2 server push allow/deny behavior.
    pub fn withAllowPush(self: ClientConfig, allow_push: bool) ClientConfig {
        var out = self;
        out.allow_push = allow_push;
        return out;
    }

    /// Returns a copy with explicit HTTP/2 settings.
    pub fn withHTTP2Settings(self: ClientConfig, settings: types.HTTP2Settings) ClientConfig {
        var out = self;
        out.http2_settings = settings;
        return out;
    }

    /// Returns a copy with explicit HTTP/3 settings.
    pub fn withHTTP3Settings(self: ClientConfig, settings: types.HTTP3Settings) ClientConfig {
        var out = self;
        out.http3_settings = settings;
        return out;
    }

    /// Returns a copy with SSL verification behavior.
    pub fn withSslVerification(self: ClientConfig, verify_ssl: bool) ClientConfig {
        var out = self;
        out.verify_ssl = verify_ssl;
        return out;
    }

    /// Returns a copy with keep-alive enablement.
    pub fn withKeepAlive(self: ClientConfig, keep_alive: bool) ClientConfig {
        var out = self;
        out.keep_alive = keep_alive;
        return out;
    }

    /// Returns a copy with maximum response-size limit.
    pub fn withMaxResponseSize(self: ClientConfig, max_response_size: usize) ClientConfig {
        var out = self;
        out.max_response_size = max_response_size;
        return out;
    }

    /// Returns a copy with connection-pool limits.
    pub fn withPoolLimits(self: ClientConfig, max_connections: u32, max_per_host: u32) ClientConfig {
        var out = self;
        out.pool_max_connections = max_connections;
        out.pool_max_per_host = max_per_host;
        return out;
    }
};

/// Basic authentication credentials used by per-request options.
pub const BasicAuth = struct {
    username: []const u8,
    password: []const u8,
};

/// Representation of a multipart form field.
pub const MultipartField = struct {
    name: []const u8,
    value: []const u8,
};

/// Representation of a multipart upload file.
pub const MultipartFile = struct {
    name: []const u8,
    filename: []const u8,
    content_type: ?[]const u8 = null,
    data: []const u8,
};

/// Per-request options.
pub const RequestOptions = struct {
    headers: ?[]const [2][]const u8 = null,
    query_params: ?[]const [2][]const u8 = null,
    body: ?[]const u8 = null,
    json: ?[]const u8 = null,
    form_fields: ?[]const [2][]const u8 = null,
    bearer_token: ?[]const u8 = null,
    basic_auth: ?BasicAuth = null,
    timeout_ms: ?u64 = null,
    connect_timeout_ms: ?u64 = null,
    read_timeout_ms: ?u64 = null,
    write_timeout_ms: ?u64 = null,
    timeouts: ?types.Timeouts = null,
    /// Optional borrowed cancellation token. It must outlive the request.
    /// The client only observes this token and never signals it.
    cancel_token: ?*const types.CancellationToken = null,
    policy: types.RequestPolicyOverrides = .{},
    version: ?types.Version = null,
    multipart_fields: ?[]const MultipartField = null,
    multipart_files: ?[]const MultipartFile = null,
    multipart_boundary: ?[]const u8 = null,
    proxy: ?types.Proxy = null,
    verify_ssl: ?bool = null,
    keep_alive: ?bool = null,
    unix_socket_path: ?[]const u8 = null,
    range_header: ?[]const u8 = null,
    api_key_header: ?[]const u8 = null,
    api_key_value: ?[]const u8 = null,
    expect_100_continue: bool = false,

    /// Returns default request options.
    pub fn defaults() RequestOptions {
        return .{};
    }

    /// Returns a copy with request headers.
    pub fn withHeaders(self: RequestOptions, headers: []const [2][]const u8) RequestOptions {
        var out = self;
        out.headers = headers;
        return out;
    }

    /// Returns a copy with a custom proxy configuration for this request.
    pub fn withProxy(self: RequestOptions, proxy: ?types.Proxy) RequestOptions {
        var out = self;
        out.proxy = proxy;
        return out;
    }

    /// Returns a copy with explicit SSL verification behavior for this request.
    pub fn withSslVerification(self: RequestOptions, verify_ssl: bool) RequestOptions {
        var out = self;
        out.verify_ssl = verify_ssl;
        return out;
    }

    /// Returns a copy with explicit keep-alive behavior for this request.
    pub fn withKeepAlive(self: RequestOptions, keep_alive: bool) RequestOptions {
        var out = self;
        out.keep_alive = keep_alive;
        return out;
    }

    /// Returns a copy with a custom Unix domain socket path for this request.
    pub fn withUnixSocket(self: RequestOptions, path: ?[]const u8) RequestOptions {
        var out = self;
        out.unix_socket_path = path;
        return out;
    }

    /// Returns a copy with a Range header for partial content requests.
    /// Supports "bytes=start-end", "bytes=start-", and "bytes=-suffix" formats.
    pub fn withRange(self: RequestOptions, range: []const u8) RequestOptions {
        var out = self;
        out.range_header = range;
        return out;
    }

    /// Returns a copy with a byte range request (e.g., "bytes=0-499").
    pub fn withByteRange(self: RequestOptions, start: u64, end: ?u64) RequestOptions {
        var buf: [64]u8 = undefined;
        const range_str = if (end) |e|
            std.fmt.bufPrint(&buf, "bytes={d}-{d}", .{ start, e }) catch return self
        else
            std.fmt.bufPrint(&buf, "bytes={d}-", .{start}) catch return self;
        return self.withRange(range_str);
    }

    /// Returns a copy with a suffix range (last N bytes, e.g., "bytes=-500").
    pub fn withSuffixRange(self: RequestOptions, suffix_len: u64) RequestOptions {
        var buf: [64]u8 = undefined;
        const range_str = std.fmt.bufPrint(&buf, "bytes=-{d}", .{suffix_len}) catch return self;
        return self.withRange(range_str);
    }

    /// Returns a copy with multipart fields.
    pub fn withMultipartFields(self: RequestOptions, fields: []const MultipartField) RequestOptions {
        var out = self;
        out.multipart_fields = fields;
        return out;
    }

    /// Returns a copy with multipart files.
    pub fn withMultipartFiles(self: RequestOptions, files: []const MultipartFile) RequestOptions {
        var out = self;
        out.multipart_files = files;
        return out;
    }

    /// Returns a copy with a custom boundary for multipart request.
    pub fn withMultipartBoundary(self: RequestOptions, boundary: []const u8) RequestOptions {
        var out = self;
        out.multipart_boundary = boundary;
        return out;
    }

    /// Returns a copy with query parameters to append to the request URL.
    pub fn withQueryParams(self: RequestOptions, query_params: []const [2][]const u8) RequestOptions {
        var out = self;
        out.query_params = query_params;
        return out;
    }

    /// Returns a copy with a raw request body.
    pub fn withBody(self: RequestOptions, body: []const u8) RequestOptions {
        var out = self;
        out.body = body;
        return out;
    }

    /// Returns a copy with a JSON request body.
    pub fn withJson(self: RequestOptions, json: []const u8) RequestOptions {
        var out = self;
        out.json = json;
        return out;
    }

    /// Returns a copy with form fields encoded as application/x-www-form-urlencoded.
    pub fn withFormUrlEncoded(self: RequestOptions, form_fields: []const [2][]const u8) RequestOptions {
        var out = self;
        out.form_fields = form_fields;
        return out;
    }

    /// Returns a copy that sets `Authorization: Bearer <token>` for this request.
    /// This clears any previously set basic-auth credentials in the options copy.
    pub fn withBearerToken(self: RequestOptions, token: []const u8) RequestOptions {
        var out = self;
        out.bearer_token = token;
        out.basic_auth = null;
        return out;
    }

    /// Returns a copy that sets `Authorization: Basic ...` for this request.
    /// This clears any previously set bearer token in the options copy.
    pub fn withBasicAuth(self: RequestOptions, username: []const u8, password: []const u8) RequestOptions {
        var out = self;
        out.basic_auth = .{ .username = username, .password = password };
        out.bearer_token = null;
        return out;
    }

    /// Returns a copy that sets an API key in the specified header.
    /// Common patterns: `X-API-Key`, `Authorization: ApiKey <key>`, or custom headers.
    pub fn withApiKey(self: RequestOptions, header_name: []const u8, key: []const u8) RequestOptions {
        var out = self;
        out.api_key_header = header_name;
        out.api_key_value = key;
        return out;
    }

    /// Returns a copy that sets `Expect: 100-continue` for this request.
    /// The client will wait for a 100 Continue response before sending the body.
    pub fn withExpect100Continue(self: RequestOptions) RequestOptions {
        var out = self;
        out.expect_100_continue = true;
        return out;
    }

    /// Returns a copy with a per-request uniform timeout across connect/read/write phases.
    pub fn withTimeoutMs(self: RequestOptions, timeout_ms: u64) RequestOptions {
        var out = self;
        out.timeout_ms = timeout_ms;
        return out;
    }

    /// Returns a copy with explicit per-phase timeouts struct.
    pub fn withTimeouts(self: RequestOptions, timeouts: types.Timeouts) RequestOptions {
        var out = self;
        out.timeouts = timeouts;
        return out;
    }

    /// Returns a copy that observes a borrowed cancellation token.
    pub fn withCancellation(self: RequestOptions, cancel_token: ?*const types.CancellationToken) RequestOptions {
        var out = self;
        out.cancel_token = cancel_token;
        return out;
    }

    /// Returns a copy with explicit connect phase timeout in milliseconds.
    pub fn withConnectTimeoutMs(self: RequestOptions, connect_timeout_ms: u64) RequestOptions {
        var out = self;
        out.connect_timeout_ms = connect_timeout_ms;
        return out;
    }

    /// Returns a copy with explicit read phase timeout in milliseconds.
    pub fn withReadTimeoutMs(self: RequestOptions, read_timeout_ms: u64) RequestOptions {
        var out = self;
        out.read_timeout_ms = read_timeout_ms;
        return out;
    }

    /// Returns a copy with explicit write phase timeout in milliseconds.
    pub fn withWriteTimeoutMs(self: RequestOptions, write_timeout_ms: u64) RequestOptions {
        var out = self;
        out.write_timeout_ms = write_timeout_ms;
        return out;
    }

    /// Returns a copy with per-feature automatic-policy overrides.
    pub fn withPolicy(self: RequestOptions, policy: types.RequestPolicyOverrides) RequestOptions {
        var out = self;
        out.policy = policy;
        return out;
    }

    /// Compatibility helper for the former per-request redirect flag.
    /// Enabling uses the managed redirect defaults; use `withPolicy` to supply
    /// a custom `RedirectPolicy`.
    pub fn withFollowRedirects(self: RequestOptions, follow_redirects: bool) RequestOptions {
        var out = self;
        out.policy.redirect = if (follow_redirects) .{ .policy = .{} } else .disabled;
        return out;
    }

    /// Returns a copy with an explicit HTTP version for this request.
    pub fn withVersion(self: RequestOptions, version: types.Version) RequestOptions {
        var out = self;
        out.version = version;
        return out;
    }

    /// Returns a copy that forces this request through the HTTP/2 runtime path.
    pub fn withHTTP2(self: RequestOptions) RequestOptions {
        return self.withVersion(.HTTP_2);
    }

    /// Returns a copy that forces this request through the HTTP/3 runtime path.
    pub fn withHTTP3(self: RequestOptions) RequestOptions {
        return self.withVersion(.HTTP_3);
    }
};

/// Immutable metadata for one transport attempt.
///
/// `attempt` is one-based and resets after each followed redirect.
/// `redirect_count` is zero for the original URL. Slices are borrowed for the
/// duration of the callback. Callbacks may run concurrently and reentrantly.
pub const AttemptContext = struct {
    logical_request_id: u64,
    attempt: u32,
    redirect_count: u32,
    policy: types.EffectiveClientPolicy,
    url: []const u8,
};

pub const RequestInterceptor = *const fn (*Request, *const AttemptContext, ?*anyopaque) anyerror!void;
pub const ResponseInterceptor = *const fn (*Response, *const AttemptContext, ?*anyopaque) anyerror!void;
pub const ErrorInterceptor = *const fn (anyerror, *const AttemptContext, ?*anyopaque) void;
/// Called after an attempt result has been observed and a retry will occur.
pub const RetryInterceptor = *const fn (*const AttemptContext, ?*anyopaque) void;
/// Called after a redirect response has been observed and will be followed.
pub const RedirectInterceptor = *const fn ([]const u8, *const AttemptContext, ?*anyopaque) void;

/// Interceptor with context.
pub const Interceptor = struct {
    request_fn: ?RequestInterceptor = null,
    response_fn: ?ResponseInterceptor = null,
    error_fn: ?ErrorInterceptor = null,
    retry_fn: ?RetryInterceptor = null,
    redirect_fn: ?RedirectInterceptor = null,
    context: ?*anyopaque = null,
};

/// Stored cookie metadata for the client cookie jar.
pub const CookieEntry = struct {
    value: []const u8,
    path: []const u8 = "/",
    domain: []const u8 = "",
    secure: bool = false,
    http_only: bool = false,
    same_site: ?common.SameSite = null,
    max_age: ?i64 = null,
    stored_at: i64 = 0,
};

fn freeCookieEntry(allocator: Allocator, entry: CookieEntry) void {
    allocator.free(entry.value);
    allocator.free(entry.path);
    allocator.free(entry.domain);
}

const ClientState = struct {
    backing_allocator: Allocator,
    allocator_lock: std.atomic.Mutex = .unlocked,
    interceptor_lock: std.atomic.Mutex = .unlocked,
    cookie_lock: std.atomic.Mutex = .unlocked,
    config: ClientConfig,
    interceptors: std.ArrayList(Interceptor) = .empty,
    cookies: std.StringHashMapUnmanaged(CookieEntry) = .{},
    pool: ConnectionPool,
    closing: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    in_flight: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    next_request_id: std.atomic.Value(u64) = std.atomic.Value(u64).init(1),

    fn lock(mutex: *std.atomic.Mutex) void {
        while (!mutex.tryLock()) std.Thread.yield() catch {};
    }

    fn allocator(self: *ClientState) Allocator {
        return .{ .ptr = self, .vtable = &allocator_vtable };
    }

    fn allocatorAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *ClientState = @ptrCast(@alignCast(ctx));
        lock(&self.allocator_lock);
        defer self.allocator_lock.unlock();
        return self.backing_allocator.vtable.alloc(self.backing_allocator.ptr, len, alignment, ret_addr);
    }

    fn allocatorResize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *ClientState = @ptrCast(@alignCast(ctx));
        lock(&self.allocator_lock);
        defer self.allocator_lock.unlock();
        return self.backing_allocator.vtable.resize(self.backing_allocator.ptr, memory, alignment, new_len, ret_addr);
    }

    fn allocatorRemap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *ClientState = @ptrCast(@alignCast(ctx));
        lock(&self.allocator_lock);
        defer self.allocator_lock.unlock();
        return self.backing_allocator.vtable.remap(self.backing_allocator.ptr, memory, alignment, new_len, ret_addr);
    }

    fn allocatorFree(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *ClientState = @ptrCast(@alignCast(ctx));
        lock(&self.allocator_lock);
        defer self.allocator_lock.unlock();
        self.backing_allocator.vtable.free(self.backing_allocator.ptr, memory, alignment, ret_addr);
    }

    const allocator_vtable = Allocator.VTable{
        .alloc = allocatorAlloc,
        .resize = allocatorResize,
        .remap = allocatorRemap,
        .free = allocatorFree,
    };
};

/// Thread-safe HTTP client handle.
///
/// Request methods, cookie operations, interceptor registration, and pool
/// inspection may be called concurrently. Interceptors and log callbacks may
/// also run concurrently and reentrantly. `deinit` is exclusive and is valid
/// only after all requests have completed and all responses are no longer used.
pub const Client = struct {
    allocator: Allocator,
    shared: *ClientState,

    const Self = @This();

    /// Creates a new HTTP client with default configuration.
    pub fn init(allocator: Allocator) Self {
        return initWithConfig(allocator, .{});
    }

    /// Creates a new HTTP client with custom configuration.
    pub fn initWithConfig(allocator: Allocator, config: ClientConfig) Self {
        const shared = allocator.create(ClientState) catch @panic("httpx.Client state allocation failed");
        shared.* = .{
            .backing_allocator = allocator,
            .config = config,
            .pool = undefined,
        };
        const synchronized_allocator = shared.allocator();
        shared.pool = ConnectionPool.initWithConfig(synchronized_allocator, .{
            .max_connections = config.pool_max_connections,
            .max_per_host = config.pool_max_per_host,
            .connect_timeout_ms = config.timeouts.connect_ms,
            .idle_timeout_ms = if (config.timeouts.idle_ms > 0) @intCast(config.timeouts.idle_ms) else 60_000,
            .dns_resolver = config.dns_resolver,
        });
        return .{
            .allocator = synchronized_allocator,
            .shared = shared,
        };
    }

    /// Creates a new client with default settings and a base URL.
    pub fn initForBaseUrl(allocator: Allocator, base_url: []const u8) Self {
        return initWithConfig(allocator, ClientConfig.forBaseUrl(base_url));
    }

    /// Releases all allocated resources.
    pub fn deinit(self: *Self) void {
        self.shared.closing.store(true, .release);
        std.debug.assert(self.shared.in_flight.load(.acquire) == 0);

        self.shared.pool.deinit();
        self.shared.interceptors.deinit(self.allocator);
        var it = self.shared.cookies.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            freeCookieEntry(self.allocator, entry.value_ptr.*);
        }
        self.shared.cookies.deinit(self.allocator);
        const backing_allocator = self.shared.backing_allocator;
        backing_allocator.destroy(self.shared);
    }

    /// Returns the immutable configuration snapshot captured at initialization.
    pub fn configuration(self: *const Self) *const ClientConfig {
        return &self.shared.config;
    }

    fn beginRequest(self: *Self) !u64 {
        if (self.shared.closing.load(.acquire)) return error.ClientClosed;
        _ = self.shared.in_flight.fetchAdd(1, .acq_rel);
        if (self.shared.closing.load(.acquire)) {
            _ = self.shared.in_flight.fetchSub(1, .acq_rel);
            return error.ClientClosed;
        }
        return self.shared.next_request_id.fetchAdd(1, .monotonic);
    }

    fn endRequest(self: *Self) void {
        _ = self.shared.in_flight.fetchSub(1, .acq_rel);
    }

    fn snapshotInterceptors(self: *Self) ![]Interceptor {
        ClientState.lock(&self.shared.interceptor_lock);
        defer self.shared.interceptor_lock.unlock();
        return self.allocator.dupe(Interceptor, self.shared.interceptors.items);
    }

    fn isRequestSingletonHeader(name: []const u8) bool {
        return std.ascii.eqlIgnoreCase(name, HeaderName.HOST) or
            std.ascii.eqlIgnoreCase(name, HeaderName.CONTENT_LENGTH) or
            std.ascii.eqlIgnoreCase(name, HeaderName.TRANSFER_ENCODING) or
            std.ascii.eqlIgnoreCase(name, HeaderName.USER_AGENT) or
            std.ascii.eqlIgnoreCase(name, HeaderName.AUTHORIZATION) or
            std.ascii.eqlIgnoreCase(name, HeaderName.PROXY_AUTHORIZATION) or
            std.ascii.eqlIgnoreCase(name, HeaderName.CONTENT_TYPE) or
            std.ascii.eqlIgnoreCase(name, HeaderName.RANGE) or
            std.ascii.eqlIgnoreCase(name, HeaderName.REFERER);
    }

    fn applyConfiguredHeaders(req: *Request, configured: []const [2][]const u8) !void {
        for (configured) |header| {
            if (isRequestSingletonHeader(header[0])) {
                try req.headers.set(header[0], header[1]);
            } else {
                try req.headers.append(header[0], header[1]);
            }
        }
    }

    fn validateRequestHeaders(req: *const Request) !void {
        var host_count: usize = 0;
        var content_length_count: usize = 0;
        var transfer_encoding_count: usize = 0;
        var content_length: ?usize = null;

        for (req.headers.iterator()) |header| {
            if (isRequestSingletonHeader(header.name)) {
                var duplicate_count: usize = 0;
                for (req.headers.iterator()) |candidate| {
                    if (std.ascii.eqlIgnoreCase(candidate.name, header.name)) duplicate_count += 1;
                }
                if (duplicate_count > 1) return error.DuplicateSingletonHeader;
            }
            if (std.ascii.eqlIgnoreCase(header.name, HeaderName.HOST)) {
                host_count += 1;
                if (mem.trim(u8, header.value, " \t").len == 0) return error.InvalidHostHeader;
            } else if (std.ascii.eqlIgnoreCase(header.name, HeaderName.CONTENT_LENGTH)) {
                content_length_count += 1;
                content_length = std.fmt.parseInt(usize, mem.trim(u8, header.value, " \t"), 10) catch
                    return error.InvalidContentLength;
            } else if (std.ascii.eqlIgnoreCase(header.name, HeaderName.TRANSFER_ENCODING)) {
                transfer_encoding_count += 1;
            }
        }

        if (host_count != 1) return error.InvalidHostHeader;
        if (content_length_count > 1 or transfer_encoding_count > 1) {
            return error.DuplicateFramingHeader;
        }
        if (content_length_count > 0 and transfer_encoding_count > 0) {
            return error.ConflictingFramingHeaders;
        }
        if (transfer_encoding_count > 0) return error.UnsupportedTransferEncoding;

        const body_len = if (req.body) |body| body.len else 0;
        if (content_length) |declared| {
            if (declared != body_len) return error.InvalidContentLength;
        } else if (body_len > 0) {
            return error.MissingContentLength;
        }
    }

    /// Resolves a hostname to a single address using the configured DNS resolver
    /// (if any) or falling back to the system resolver.
    fn resolveAddress(
        self: *Self,
        hostname: []const u8,
        port: u16,
        context: *const IoContext,
    ) !address_mod.Address {
        try context.check();
        if (self.shared.config.dns_resolver) |resolver| {
            var result = try resolver.resolveWithContext(hostname, .{ .port = port }, context);
            defer result.deinit();
            if (result.addresses.len == 0) return error.DNSResolutionFailed;
            return result.addresses[0];
        }

        // The platform getaddrinfo path is blocking and cannot be
        // synchronously cancelled. Check immediately before and after it.
        const resolved = address_mod.resolve(self.allocator, hostname, port);
        return context.unwrapAfterBlocking(address_mod.Address, resolved);
    }

    /// Logs a formatted message. If config.log_fn is provided, delegates to it.
    /// Otherwise, silently drops the message. Client does not print internally.
    pub fn log(self: *const Self, level: server_mod.LogLevel, comptime format: []const u8, args: anytype) void {
        if (@intFromEnum(level) < @intFromEnum(self.shared.config.log_level)) return;
        if (self.shared.config.log_fn) |log_fn| {
            var buf: [1024]u8 = undefined;
            if (std.fmt.bufPrint(&buf, format, args)) |msg| {
                log_fn(level, msg);
            } else |_| {
                log_fn(level, "[Log format failed or message too long]");
            }
        }
    }

    /// Adds an interceptor to the client.
    pub fn addInterceptor(self: *Self, interceptor: Interceptor) !void {
        ClientState.lock(&self.shared.interceptor_lock);
        defer self.shared.interceptor_lock.unlock();
        try self.shared.interceptors.append(self.allocator, interceptor);
    }

    /// Removes idle or exhausted pooled connections based on pool policy.
    pub fn cleanupIdleConnections(self: *Self) void {
        self.shared.pool.cleanup();
    }

    /// Returns a snapshot of total/active/idle pooled connection counts.
    pub fn poolStats(self: *Self) PoolStats {
        return self.shared.pool.stats();
    }

    /// Returns how many pooled connections are tracked for a host/port.
    pub fn hostPoolConnectionCount(self: *Self, host: []const u8, port: u16) usize {
        return self.shared.pool.hostConnectionCount(host, port);
    }

    /// Makes an HTTP request.
    pub fn request(self: *Self, method: types.Method, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.requestInternal(method, url, reqOpts);
    }

    /// Alias for request() with a shorter name for application code.
    pub fn send(self: *Self, method: types.Method, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(method, url, reqOpts);
    }

    /// Alias for GET requests in fetch-style client code.
    pub fn fetch(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.get(url, reqOpts);
    }

    fn requestInternal(self: *Self, method: types.Method, url: []const u8, reqOpts: RequestOptions) !Response {
        const logical_request_id = try self.beginRequest();
        defer self.endRequest();
        const effective_policy = self.shared.config.policy.resolve(reqOpts.policy);
        const timeouts = self.resolveRequestTimeouts(reqOpts);
        const context = IoContext.init(.{
            .external_cancel = reqOpts.cancel_token,
            .request_deadline = if (timeouts.request_ms > 0) Deadline.afterMs(timeouts.request_ms) else null,
        });
        return self.requestWithPolicy(method, url, reqOpts, &effective_policy, &context, logical_request_id, 0);
    }

    fn requestWithPolicy(
        self: *Self,
        method: types.Method,
        url: []const u8,
        reqOpts: RequestOptions,
        effective_policy: *const types.EffectiveClientPolicy,
        context: *const IoContext,
        logical_request_id: u64,
        depth: u32,
    ) !Response {
        try checkRequestContext(context);

        const full_url = if (self.shared.config.base_url) |base| blk: {
            if (mem.indexOf(u8, url, "://") != null) break :blk try self.allocator.dupe(u8, url);
            break :blk try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ base, url });
        } else try self.allocator.dupe(u8, url);
        defer self.allocator.free(full_url);

        var req = try Request.init(self.allocator, method, full_url);
        defer req.deinit();

        if (reqOpts.version) |version| {
            req.version = version;
        }

        if (self.shared.config.default_headers) |hdrs| {
            try applyConfiguredHeaders(&req, hdrs);
        }

        if (reqOpts.headers) |hdrs| {
            try applyConfiguredHeaders(&req, hdrs);
        }

        if (effective_policy.user_agent == .enabled and
            !req.headers.contains(HeaderName.USER_AGENT) and
            self.shared.config.user_agent.len > 0)
        {
            try req.headers.append(HeaderName.USER_AGENT, self.shared.config.user_agent);
        }

        if (!req.headers.contains(HeaderName.ACCEPT_ENCODING)) {
            if (effective_policy.accept_encoding.value()) |value| {
                try req.headers.append(HeaderName.ACCEPT_ENCODING, value);
            }
        }

        if (reqOpts.query_params) |params| {
            try req.addQueryParams(params);
        }

        if (reqOpts.body) |body| {
            try req.setBody(body);
        } else if (reqOpts.json) |json_body| {
            try req.setJson(json_body);
        } else if (reqOpts.form_fields) |fields| {
            try req.setFormUrlEncoded(fields);
        } else if (reqOpts.multipart_fields != null or reqOpts.multipart_files != null) {
            const boundary = reqOpts.multipart_boundary orelse "----httpxBoundary1234567890";
            var builder = @import("../data/multipart.zig").MultipartBuilder.init(self.allocator, boundary);
            defer builder.deinit();

            if (reqOpts.multipart_fields) |fields| {
                for (fields) |field| {
                    try builder.addField(field.name, field.value);
                }
            }

            if (reqOpts.multipart_files) |files| {
                for (files) |file| {
                    const resolved_mime = file.content_type orelse common.mimeTypeFromPathOr(file.filename, "application/octet-stream");

                    try builder.addFile(file.name, file.filename, resolved_mime, file.data);
                }
            }

            const body = try builder.build();
            defer self.allocator.free(body);
            try req.setBody(body);

            const ct = try builder.contentType();
            defer self.allocator.free(ct);
            try req.headers.set(HeaderName.CONTENT_TYPE, ct);
        }

        if (reqOpts.range_header) |range| {
            try req.headers.set(HeaderName.RANGE, range);
        }

        if (reqOpts.api_key_header) |header_name| {
            if (reqOpts.api_key_value) |key_value| {
                try req.headers.set(header_name, key_value);
            }
        }

        if (reqOpts.expect_100_continue) {
            try req.headers.set(HeaderName.EXPECT, "100-continue");
        }

        // Enforce request size limit.
        if (req.body) |body| {
            if (body.len > self.shared.config.max_request_size) {
                return error.RequestTooLarge;
            }
        }

        // Compress request body if configured.
        if (req.body) |body| {
            if (body.len > 0 and self.shared.config.request_compression != null) {
                if (req.headers.get("Content-Encoding") == null) {
                    const ct = req.headers.get("Content-Type") orelse "";
                    if (compression_util.isCompressible(ct)) {
                        if (compression_util.compressWithLevel(
                            self.allocator,
                            .gzip,
                            body,
                            self.shared.config.request_compression.?,
                        )) |compressed| {
                            if (req.body_owned) self.allocator.free(body);
                            req.body = compressed;
                            req.body_owned = true;
                            try req.headers.set("Content-Encoding", "gzip");
                            var len_buf: [32]u8 = undefined;
                            const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{compressed.len}) catch unreachable;
                            try req.headers.set(HeaderName.CONTENT_LENGTH, len_str);
                            try req.headers.set("Vary", "Content-Encoding");
                        } else |_| {}
                    }
                }
            }
        }

        if (reqOpts.basic_auth) |basic| {
            try req.setBasicAuth(basic.username, basic.password);
        }
        if (reqOpts.bearer_token) |token| {
            try req.setBearerAuth(token);
        }

        if (effective_policy.cookies.sends()) {
            try self.attachCookies(&req);
        }

        const execution = try self.executeRequest(
            &req,
            reqOpts,
            effective_policy,
            context,
            logical_request_id,
            depth,
            full_url,
        );
        var response = execution.response;

        if (response.isRedirect()) {
            const redirect_policy = effective_policy.redirectPolicy() orelse return response;
            if (depth >= redirect_policy.max_redirects) {
                if (self.shared.config.metrics) |m| m.redirectFailed();
                response.deinit();
                return error.TooManyRedirects;
            }

            const location = response.headers.get(HeaderName.LOCATION) orelse {
                response.deinit();
                return error.InvalidResponse;
            };

            const next_url = try self.resolveRedirectUrl(req.uri, location);
            defer self.allocator.free(next_url);

            const attempt_context = AttemptContext{
                .logical_request_id = logical_request_id,
                .attempt = execution.attempt,
                .redirect_count = depth,
                .policy = effective_policy.*,
                .url = full_url,
            };
            const interceptors = try self.snapshotInterceptors();
            defer self.allocator.free(interceptors);
            for (interceptors) |interceptor| {
                if (interceptor.redirect_fn) |fn_ptr| {
                    fn_ptr(next_url, &attempt_context, interceptor.context);
                }
            }

            const next_method = redirect_policy.getRedirectMethod(response.status.code, req.method);

            // Security: strip credentials on cross-origin redirects (RFC 6454).
            var next_opts = reqOpts;
            var safe_headers = std.ArrayList([2][]const u8).empty;
            if (!isSameOrigin(req.uri.host orelse "", next_url)) {
                // Strip Authorization header to prevent credential leakage.
                if (next_opts.headers) |hdrs| {
                    for (hdrs) |h| {
                        if (!std.ascii.eqlIgnoreCase(h[0], "Authorization") and
                            !std.ascii.eqlIgnoreCase(h[0], "Proxy-Authorization"))
                        {
                            safe_headers.append(self.allocator, h) catch break;
                        }
                    }
                    next_opts.headers = safe_headers.items;
                }
                // Clear auth fields.
                next_opts.bearer_token = null;
                next_opts.basic_auth = null;
            }

            response.deinit();
            defer safe_headers.deinit(self.allocator);
            if (self.shared.config.metrics) |m| m.redirect();
            return self.requestWithPolicy(
                next_method,
                next_url,
                next_opts,
                effective_policy,
                context,
                logical_request_id,
                depth + 1,
            );
        }

        return response;
    }

    fn normalizeRequestContextError(context: *const IoContext, err: anyerror) anyerror {
        if (err == error.Timeout and context.expiredDeadline() != null) {
            return error.RequestTimeout;
        }
        return err;
    }

    fn checkRequestContext(context: *const IoContext) !void {
        context.check() catch |err| return normalizeRequestContextError(context, err);
    }

    fn waitForRetry(context: *const IoContext, delay_ms: u64) !void {
        context.waitForMs(delay_ms) catch |err| return normalizeRequestContextError(context, err);
    }

    const RequestExecution = struct {
        response: Response,
        attempt: u32,
    };

    /// Executes all transport attempts for one URL in a logical request.
    fn executeRequest(
        self: *Self,
        req: *Request,
        reqOpts: RequestOptions,
        effective_policy: *const types.EffectiveClientPolicy,
        context: *const IoContext,
        logical_request_id: u64,
        redirect_count: u32,
        url: []const u8,
    ) !RequestExecution {
        if (self.shared.config.metrics) |m| m.recordRequest();
        const start_time_ms: u64 = @intCast(@max(common.nowMillis(), 0));
        const retry_policy = effective_policy.retryPolicy();
        const can_retry_method = if (retry_policy) |policy|
            (!policy.retry_only_idempotent) or req.method.isIdempotent()
        else
            false;

        var attempt: u32 = 1;
        while (true) {
            checkRequestContext(context) catch |err| {
                if (self.shared.config.metrics) |m| m.recordError();
                return err;
            };

            const attempt_context = AttemptContext{
                .logical_request_id = logical_request_id,
                .attempt = attempt,
                .redirect_count = redirect_count,
                .policy = effective_policy.*,
                .url = url,
            };
            const interceptors = try self.snapshotInterceptors();
            defer self.allocator.free(interceptors);

            for (interceptors) |interceptor| {
                if (interceptor.request_fn) |callback| {
                    try callback(req, &attempt_context, interceptor.context);
                }
            }
            try validateRequestHeaders(req);

            var res = self.executeRequestOnce(req, reqOpts, effective_policy, context) catch |raw_err| {
                const err = normalizeRequestContextError(context, raw_err);
                for (interceptors) |interceptor| {
                    if (interceptor.error_fn) |callback| {
                        callback(err, &attempt_context, interceptor.context);
                    }
                }
                if (retry_policy) |policy| {
                    if (policy.retry_on_connection_error and can_retry_method and attempt <= policy.max_retries and isRetryableRequestError(err)) {
                        checkRequestContext(context) catch |context_err| {
                            if (self.shared.config.metrics) |m| m.recordError();
                            return context_err;
                        };
                        if (self.shared.config.metrics) |m| {
                            m.recordError();
                        }
                        const delay_ms = policy.calculateDelay(attempt);
                        if (delay_ms > 0) {
                            waitForRetry(context, delay_ms) catch |context_err| {
                                if (self.shared.config.metrics) |m| m.recordError();
                                return context_err;
                            };
                        }
                        checkRequestContext(context) catch |context_err| {
                            if (self.shared.config.metrics) |m| m.recordError();
                            return context_err;
                        };
                        if (self.shared.config.metrics) |m| m.retryAttempt();
                        for (interceptors) |interceptor| {
                            if (interceptor.retry_fn) |fn_ptr| {
                                fn_ptr(&attempt_context, interceptor.context);
                            }
                        }
                        attempt += 1;
                        continue;
                    }
                }
                if (self.shared.config.metrics) |m| m.recordError();
                return err;
            };

            if (effective_policy.cookies.stores()) {
                self.storeCookies(&res, req.uri.host orelse "") catch |err| {
                    res.deinit();
                    return err;
                };
            }

            for (interceptors) |interceptor| {
                if (interceptor.response_fn) |callback| {
                    callback(&res, &attempt_context, interceptor.context) catch |err| {
                        res.deinit();
                        return err;
                    };
                }
            }

            if (retry_policy) |policy| {
                if (can_retry_method and attempt <= policy.max_retries and policy.shouldRetryStatus(res.status.code)) {
                    checkRequestContext(context) catch |err| {
                        res.deinit();
                        if (self.shared.config.metrics) |m| m.recordError();
                        return err;
                    };
                    // Parse Retry-After header if present.
                    const retry_after_ms = if (res.headers.get("Retry-After")) |ra|
                        parseRetryAfter(ra) orelse policy.calculateDelay(attempt)
                    else
                        policy.calculateDelay(attempt);
                    res.deinit();
                    if (retry_after_ms > 0) {
                        waitForRetry(context, retry_after_ms) catch |err| {
                            if (self.shared.config.metrics) |m| m.recordError();
                            return err;
                        };
                    }
                    checkRequestContext(context) catch |err| {
                        if (self.shared.config.metrics) |m| m.recordError();
                        return err;
                    };
                    if (self.shared.config.metrics) |m| m.retryAttempt();
                    for (interceptors) |interceptor| {
                        if (interceptor.retry_fn) |fn_ptr| {
                            fn_ptr(&attempt_context, interceptor.context);
                        }
                    }
                    attempt += 1;
                    continue;
                }
            }

            // Record metrics.
            if (self.shared.config.metrics) |m| {
                const now_ms: u64 = @intCast(@max(common.nowMillis(), 0));
                const elapsed_ms: u64 = now_ms -| start_time_ms;
                const latency_ns = elapsed_ms * 1_000_000;
                const body_len: u64 = if (res.body) |b| @intCast(b.len) else 0;
                m.recordResponse(res.status.code, body_len, latency_ns);
            }

            return .{ .response = res, .attempt = attempt };
        }
    }

    /// Returns true for transport-layer failures that are worth retrying.
    /// TLS/protocol/parse failures are treated as deterministic and fail fast.
    fn isRetryableRequestError(err: anyerror) bool {
        const name = @errorName(err);

        if (mem.startsWith(u8, name, "TLS")) return false;

        return !(mem.eql(u8, name, "InvalidUri") or
            mem.eql(u8, name, "InvalidResponse") or
            mem.eql(u8, name, "InvalidHeader") or
            mem.eql(u8, name, "InvalidChunkSize") or
            mem.eql(u8, name, "ProtocolError") or
            mem.eql(u8, name, "HTTP2Error") or
            mem.eql(u8, name, "HTTP3Error") or
            mem.eql(u8, name, "QUICError") or
            mem.eql(u8, name, "CompressionError") or
            mem.eql(u8, name, "Cancelled") or
            mem.eql(u8, name, "Timeout") or
            mem.eql(u8, name, "RequestTimeout") or
            mem.eql(u8, name, "ResponseTooLarge") or
            mem.eql(u8, name, "RequestTooLarge") or
            mem.eql(u8, name, "TooManyRedirects"));
    }

    /// Parses a Retry-After header value (seconds or HTTP-date) into milliseconds.
    fn parseRetryAfter(value: []const u8) ?u64 {
        const trimmed = mem.trim(u8, value, " \t\r\n");
        // Try integer seconds first.
        if (std.fmt.parseInt(u64, trimmed, 10)) |seconds| {
            return seconds * 1000;
        } else |_| {}
        // Try HTTP-date format (simplified: just return a default 60s delay).
        return null;
    }

    fn formatProxyRequest(self: *Self, req: *const Request, proxy: types.Proxy) ![]u8 {
        var buffer = std.ArrayList(u8).empty;
        const writer = list_writer.init(self.allocator, &buffer);

        const method_str = req.method.toString();
        // Construct absolute URI
        try writer.print("{s} http://{s}:{d}{s}", .{ method_str, req.uri.host orelse "", req.uri.effectivePort(), req.uri.path });
        if (req.uri.query) |q| {
            try writer.print("?{s}", .{q});
        }
        try writer.print(" {s}\r\n", .{req.version.toString()});

        for (req.headers.entries.items) |h| {
            try writer.print("{s}: {s}\r\n", .{ h.name, h.value });
        }

        if (proxy.username) |user| {
            const pass = proxy.password orelse "";
            const auth_val = try @import("../data/encoding.zig").Base64.formatBasicAuth(self.allocator, user, pass);
            defer self.allocator.free(auth_val);
            try writer.print("Proxy-Authorization: {s}\r\n", .{auth_val});
        }

        try writer.writeAll("\r\n");

        if (req.body) |body| {
            try writer.writeAll(body);
        }

        return buffer.toOwnedSlice(self.allocator);
    }

    fn establishProxyTLSTunnel(self: *Self, socket: *Socket, target_host: []const u8, target_port: u16, proxy: types.Proxy) !void {
        var buffer = std.ArrayList(u8).empty;
        const writer = list_writer.init(self.allocator, &buffer);

        try writer.print("CONNECT {s}:{d} HTTP/1.1\r\nHost: {s}:{d}\r\n", .{ target_host, target_port, target_host, target_port });

        if (proxy.username) |user| {
            const pass = proxy.password orelse "";
            const auth_val = try @import("../data/encoding.zig").Base64.formatBasicAuth(self.allocator, user, pass);
            defer self.allocator.free(auth_val);
            try writer.print("Proxy-Authorization: {s}\r\n", .{auth_val});
        }
        try writer.writeAll("\r\n");

        const connect_req = try buffer.toOwnedSlice(self.allocator);
        defer self.allocator.free(connect_req);

        try socket.sendAll(connect_req);

        var response = try self.readResponseFromTcp(socket, true, .disabled);
        defer response.deinit();

        if (response.status.code < 200 or response.status.code >= 300) {
            return error.ProxyConnectionFailed;
        }
    }

    fn resolveRequestTimeouts(self: *const Self, req_opts: RequestOptions) RequestTimeouts {
        var connect_ms = self.shared.config.timeouts.connect_ms;
        var read_ms = self.shared.config.timeouts.read_ms;
        var write_ms = self.shared.config.timeouts.write_ms;
        var request_ms = self.shared.config.timeouts.request_ms;

        if (req_opts.timeouts) |t| {
            connect_ms = t.connect_ms;
            read_ms = t.read_ms;
            write_ms = t.write_ms;
            if (t.request_ms > 0) request_ms = t.request_ms;
        }

        if (req_opts.timeout_ms) |ms| {
            connect_ms = ms;
            read_ms = ms;
            write_ms = ms;
        }

        if (req_opts.connect_timeout_ms) |c_ms| connect_ms = c_ms;
        if (req_opts.read_timeout_ms) |r_ms| read_ms = r_ms;
        if (req_opts.write_timeout_ms) |w_ms| write_ms = w_ms;

        return .{
            .connect_ms = connect_ms,
            .read_ms = read_ms,
            .write_ms = write_ms,
            .request_ms = request_ms,
        };
    }

    fn executeRequestOnce(
        self: *Self,
        req: *Request,
        reqOpts: RequestOptions,
        effective_policy: *const types.EffectiveClientPolicy,
        context: *const IoContext,
    ) !Response {
        try context.check();
        const timeouts = self.resolveRequestTimeouts(reqOpts);
        const keep_alive = reqOpts.keep_alive orelse self.shared.config.keep_alive;
        const verify_ssl = reqOpts.verify_ssl orelse self.shared.config.verify_ssl;
        const unix_socket_path = reqOpts.unix_socket_path orelse self.shared.config.unix_socket_path;

        if (unix_socket_path) |path| {
            const unix_mod = @import("../net/unix.zig");
            const unix_sock = try unix_mod.UnixClient.connect(path);
            var socket = Socket.fromHandle(unix_sock.fd);
            defer socket.close();

            if (timeouts.read_ms > 0) {
                try socket.setRecvTimeout(timeouts.read_ms);
            }
            if (timeouts.write_ms > 0) {
                try socket.setSendTimeout(timeouts.write_ms);
            }

            const request_data = try http.formatRequest(req, self.allocator);
            defer self.allocator.free(request_data);

            try socket.sendAll(request_data);
            if (self.shared.config.metrics) |m| m.recordBytesSent(@intCast(request_data.len));
            return self.readResponseFromTcp(&socket, req.method.hasResponseBody(), effective_policy.decompression);
        }

        const host = req.uri.host orelse return error.InvalidUri;
        const port = req.uri.effectivePort();

        var effective_proxy = reqOpts.proxy orelse self.shared.config.proxy;
        if (effective_proxy) |p| {
            if (p.shouldBypassProxy(host)) effective_proxy = null;
        }

        const wants_http2 = self.shared.config.http2_enabled or req.version == .HTTP_2;
        const wants_http3 = self.shared.config.http3_enabled or req.version == .HTTP_3;

        // HTTP/3 takes priority, but falls back to HTTP/2 when a proxy is
        // configured (QUIC does not support standard HTTP proxies).
        if (wants_http3) {
            if (effective_proxy != null) {
                // Fall back to HTTP/2 if also enabled; otherwise return error.
                if (wants_http2) {
                    return self.executeRequestHTTP2(req, host, port, timeouts, reqOpts, effective_policy, context);
                }
                return error.ProxyNotSupported;
            }
            return self.executeRequestHTTP3(req, host, port, timeouts, reqOpts, effective_policy, context);
        }

        if (wants_http2) {
            return self.executeRequestHTTP2(req, host, port, timeouts, reqOpts, effective_policy, context);
        }

        var request_data: []u8 = undefined;
        if (effective_proxy) |p| {
            if (p.kind == .http and !req.uri.isTLS()) {
                request_data = try self.formatProxyRequest(req, p);
            } else {
                request_data = try http.formatRequest(req, self.allocator);
            }
        } else {
            request_data = try http.formatRequest(req, self.allocator);
        }
        defer self.allocator.free(request_data);

        if (req.uri.isTLS()) {
            if (keep_alive) {
                var lease = try self.shared.pool.getLeaseWithContext(.{
                    .scheme = .tls,
                    .host = host,
                    .port = port,
                    .proxy = effective_proxy,
                    .verify_tls = verify_ssl,
                    .protocol = .http1,
                }, timeouts.connect_ms, context);
                var disposition: pool_mod.LeaseDisposition = .broken;
                defer lease.release(disposition) catch {};

                const fresh = lease.isFresh();
                const socket = lease.socket();
                if (fresh) {
                    if (effective_proxy) |proxy| {
                        if (proxy.kind == .http) {
                            try self.establishProxyTLSTunnel(socket, host, port, proxy);
                        }
                    }
                }

                const session = lease.tlsSession() orelse blk: {
                    const tls_config = if (verify_ssl)
                        TLSConfig.init(self.allocator)
                    else
                        TLSConfig.insecure(self.allocator);
                    const new_session = lease.initializeTls(tls_config);
                    if (timeouts.connect_ms > 0) try socket.setRecvTimeout(timeouts.connect_ms);
                    try self.handshakePooledTls(
                        &lease,
                        new_session,
                        host,
                        port,
                        effective_proxy == null,
                    );
                    break :blk new_session;
                };

                try socket.setRecvTimeout(timeouts.read_ms);
                try socket.setSendTimeout(timeouts.write_ms);
                try session.writeAll(request_data);
                try session.flush();
                if (self.shared.config.metrics) |metrics| metrics.recordBytesSent(@intCast(request_data.len));

                const response = try self.readResponseFromTLS(
                    session,
                    req.method.hasResponseBody(),
                    effective_policy.decompression,
                );
                disposition = if (responseIsReusable(&response, req.method.hasResponseBody()))
                    .reusable
                else
                    .draining;
                return response;
            }

            const connect_host = if (effective_proxy) |p| p.host else host;
            const connect_port = if (effective_proxy) |p| p.port else port;
            const addr = try self.resolveAddress(connect_host, connect_port, context);

            var socket = try Socket.createForAddress(addr);
            defer socket.close();

            // Do not set SO_RCVTIMEO / SO_SNDTIMEO on TLS sockets.
            // The TLS layer performs multi-step record I/O; a per-recv
            // timeout fires mid-handshake and kills the TLS state
            // machine.  The connect timeout is handled separately by
            // connectWithTimeout (which uses poll).
            try socket.setNoDelay(true);

            try socket.connectWithTimeout(addr, timeouts.connect_ms);
            try socket.setNoDelay(true);

            if (effective_proxy) |p| {
                if (p.kind == .socks5h) {
                    try proxy_mod.establishSocks5hTunnel(&socket, host, port, p);
                } else {
                    try self.establishProxyTLSTunnel(&socket, host, port, p);
                }
            }

            // Set a temporary SO_RCVTIMEO for the TLS handshake to prevent
            // blocking indefinitely. Restored after handshake in executeTLSHttp.
            if (timeouts.connect_ms > 0) {
                try socket.setRecvTimeout(timeouts.connect_ms);
            }

            return self.executeTLSHttp(&socket, host, port, request_data, verify_ssl, effective_policy.decompression);
        }

        if (keep_alive) {
            var lease = try self.shared.pool.getLeaseWithContext(.{
                .scheme = .plain,
                .host = host,
                .port = port,
                .proxy = effective_proxy,
                .verify_tls = false,
                .protocol = .http1,
            }, timeouts.connect_ms, context);
            var disposition: pool_mod.LeaseDisposition = .broken;
            defer lease.release(disposition) catch {};
            const socket = lease.socket();

            try socket.setRecvTimeout(timeouts.read_ms);
            try socket.setSendTimeout(timeouts.write_ms);
            try socket.setKeepAlive(true);

            try socket.sendAll(request_data);
            if (self.shared.config.metrics) |m| m.recordBytesSent(@intCast(request_data.len));
            const res = try self.readResponseFromTcp(socket, req.method.hasResponseBody(), effective_policy.decompression);
            disposition = if (responseIsReusable(&res, req.method.hasResponseBody()))
                .reusable
            else
                .draining;
            return res;
        }

        const connect_host = if (effective_proxy) |p| p.host else host;
        const connect_port = if (effective_proxy) |p| p.port else port;
        const addr = try self.resolveAddress(connect_host, connect_port, context);

        var socket = try Socket.createForAddress(addr);
        defer socket.close();

        if (timeouts.read_ms > 0) {
            try socket.setRecvTimeout(timeouts.read_ms);
        }
        if (timeouts.write_ms > 0) {
            try socket.setSendTimeout(timeouts.write_ms);
        }

        try socket.connectWithTimeout(addr, timeouts.connect_ms);

        if (effective_proxy) |p| {
            if (p.kind == .socks5h) {
                try proxy_mod.establishSocks5hTunnel(&socket, host, port, p);
            }
        }

        try socket.sendAll(request_data);
        if (self.shared.config.metrics) |m| m.recordBytesSent(@intCast(request_data.len));
        return self.readResponseFromTcp(&socket, req.method.hasResponseBody(), effective_policy.decompression);
    }

    fn executePooledTLSHTTP1(
        self: *Self,
        req: *Request,
        lease: *ConnectionLease,
        timeouts: RequestTimeouts,
        decompression: types.DecompressionPolicy,
    ) !Response {
        const session = lease.tlsSession() orelse return error.InvalidConnectionState;
        const socket = lease.socket();
        try socket.setRecvTimeout(timeouts.read_ms);
        try socket.setSendTimeout(timeouts.write_ms);

        const request_data = try http.formatRequest(req, self.allocator);
        defer self.allocator.free(request_data);
        try session.writeAll(request_data);
        try session.flush();
        if (self.shared.config.metrics) |metrics| metrics.recordBytesSent(@intCast(request_data.len));
        return self.readResponseFromTLS(session, req.method.hasResponseBody(), decompression);
    }

    fn executeRequestHTTP2(
        self: *Self,
        req: *Request,
        host: []const u8,
        port: u16,
        timeouts: RequestTimeouts,
        reqOpts: RequestOptions,
        effective_policy: *const types.EffectiveClientPolicy,
        context: *const IoContext,
    ) !Response {
        var effective_proxy = reqOpts.proxy orelse self.shared.config.proxy;
        if (effective_proxy) |p| {
            if (p.shouldBypassProxy(host)) effective_proxy = null;
        }
        const verify_ssl = reqOpts.verify_ssl orelse self.shared.config.verify_ssl;
        const keep_alive = reqOpts.keep_alive orelse self.shared.config.keep_alive;
        const opportunistic_http2 = req.version != .HTTP_2;

        if (keep_alive and req.uri.isTLS() and opportunistic_http2) {
            if (try self.shared.pool.tryGetLeaseWithContext(.{
                .scheme = .tls,
                .host = host,
                .port = port,
                .proxy = effective_proxy,
                .verify_tls = verify_ssl,
                .protocol = .http1,
            }, context)) |fallback_lease| {
                var lease = fallback_lease;
                var disposition: pool_mod.LeaseDisposition = .broken;
                defer lease.release(disposition) catch {};
                const response = try self.executePooledTLSHTTP1(
                    req,
                    &lease,
                    timeouts,
                    effective_policy.decompression,
                );
                disposition = if (responseIsReusable(&response, req.method.hasResponseBody()))
                    .reusable
                else
                    .draining;
                return response;
            }
        }

        if (keep_alive) {
            var lease = try self.shared.pool.getLeaseWithContext(.{
                .scheme = if (req.uri.isTLS()) .tls else .plain,
                .host = host,
                .port = port,
                .proxy = effective_proxy,
                .verify_tls = verify_ssl,
                .protocol = .http2,
            }, timeouts.connect_ms, context);
            var disposition: pool_mod.LeaseDisposition = .broken;
            defer lease.release(disposition) catch {};

            const fresh = lease.isFresh();
            const socket = lease.socket();
            if (fresh) {
                if (effective_proxy) |proxy| {
                    if (proxy.kind == .http and req.uri.isTLS()) {
                        try self.establishProxyTLSTunnel(socket, host, port, proxy);
                    }
                }
            }

            if (req.uri.isTLS()) {
                const tls_session = lease.tlsSession() orelse tls_blk: {
                    const tls_config = if (verify_ssl)
                        TLSConfig.withH2(self.allocator)
                    else
                        TLSConfig.insecureWithH2(self.allocator);
                    const new_session = lease.initializeTls(tls_config);
                    if (timeouts.connect_ms > 0) try socket.setRecvTimeout(timeouts.connect_ms);
                    try self.handshakePooledTls(
                        &lease,
                        new_session,
                        host,
                        port,
                        effective_proxy == null,
                    );
                    break :tls_blk new_session;
                };
                try socket.setRecvTimeout(timeouts.read_ms);
                try socket.setSendTimeout(timeouts.write_ms);
                const negotiated = http.negotiateVersion(tls_session.negotiatedProtocol());
                if (negotiated == .http_1_1 or negotiated == .http_1_0) {
                    if (!opportunistic_http2) return error.UnsupportedHttpVersion;
                    try lease.rekeyProtocol(.http1);
                    const response = try self.executePooledTLSHTTP1(
                        req,
                        &lease,
                        timeouts,
                        effective_policy.decompression,
                    );
                    disposition = if (responseIsReusable(&response, req.method.hasResponseBody()))
                        .reusable
                    else
                        .draining;
                    return response;
                }
                if (negotiated != .http_2) return error.UnsupportedHttpVersion;

                const h2_session = lease.h2Session();
                var transport = TLSHTTP2Transport{ .session = tls_session };
                const response = try self.executeHTTP2WithTransport(
                    req,
                    &transport,
                    effective_policy.decompression,
                    h2_session,
                );
                disposition = if (h2_session.draining) .draining else .reusable;
                return response;
            } else {
                try socket.setRecvTimeout(timeouts.read_ms);
                try socket.setSendTimeout(timeouts.write_ms);
                const h2_session = lease.h2Session();
                var transport = SocketHTTP2Transport{ .socket = socket };
                const response = try self.executeHTTP2WithTransport(
                    req,
                    &transport,
                    effective_policy.decompression,
                    h2_session,
                );
                disposition = if (h2_session.draining) .draining else .reusable;
                return response;
            }
        }

        const connect_host = if (effective_proxy) |p| p.host else host;
        const connect_port = if (effective_proxy) |p| p.port else port;
        const addr = try self.resolveAddress(connect_host, connect_port, context);

        var socket = try Socket.createForAddress(addr);
        defer socket.close();

        // Do not set SO_RCVTIMEO / SO_SNDTIMEO on sockets used for
        // TLS -- the TLS layer performs multi-step record I/O and a
        // per-recv timeout fires mid-handshake.  The connect timeout
        // is handled separately by connectWithTimeout.

        try socket.connectWithTimeout(addr, timeouts.connect_ms);

        if (effective_proxy) |p| {
            if (p.kind == .socks5h) {
                try proxy_mod.establishSocks5hTunnel(&socket, host, port, p);
            } else {
                try self.establishProxyTLSTunnel(&socket, host, port, p);
            }
        }

        if (req.uri.isTLS()) {
            // Build ALPN list based on enabled protocols.
            // When both HTTP/2 and HTTP/3 are enabled, advertise all three.
            const tls_session_cfg = blk: {
                if (self.shared.config.http3_enabled and self.shared.config.http2_enabled) {
                    break :blk if (verify_ssl)
                        TLSConfig.withH3(self.allocator)
                    else
                        TLSConfig.insecureWithH3(self.allocator);
                } else if (verify_ssl) {
                    break :blk TLSConfig.withH2(self.allocator);
                } else {
                    break :blk TLSConfig.insecureWithH2(self.allocator);
                }
            };
            var session = TLSSession.init(tls_session_cfg);
            defer session.deinit();
            session.attachSocket(&socket);

            // Set a temporary SO_RCVTIMEO for the TLS handshake to prevent
            // it from blocking indefinitely. The TLS layer performs multi-step
            // record I/O, but a timeout here is better than no timeout at all.
            // After handshake completes, we either restore the original timeout
            // or set the configured read timeout.
            const tls_handshake_timeout = timeouts.connect_ms;
            if (tls_handshake_timeout > 0) {
                try socket.setRecvTimeout(tls_handshake_timeout);
            }
            const handshake_result = session.handshake(host);
            // Restore or set appropriate timeout after handshake.
            if (timeouts.read_ms > 0) {
                try socket.setRecvTimeout(timeouts.read_ms);
            }
            try handshake_result;

            const negotiated = http.negotiateVersion(session.negotiatedProtocol());
            switch (negotiated) {
                .http_2 => {
                    var h2_session = pool_mod.H2SessionState.init(self.allocator);
                    defer h2_session.deinit();
                    var transport = TLSHTTP2Transport{ .session = &session };
                    return self.executeHTTP2WithTransport(req, &transport, effective_policy.decompression, &h2_session);
                },
                .http_3 => {
                    // Server selected h3 via ALPN.  For TLS-based connections
                    // (TCP), HTTP/3 negotiation means the server prefers QUIC
                    // but we are on a TCP socket.  Attempt to upgrade via
                    // Alt-Svc or fall back to HTTP/2 if available.
                    if (self.shared.config.http2_enabled) {
                        var h2_session = pool_mod.H2SessionState.init(self.allocator);
                        defer h2_session.deinit();
                        var transport = TLSHTTP2Transport{ .session = &session };
                        return self.executeHTTP2WithTransport(req, &transport, effective_policy.decompression, &h2_session);
                    }
                    return error.UnsupportedHttpVersion;
                },
                .http_1_1, .http_1_0 => {
                    // Server selected http/1.1 via ALPN (or ALPN was
                    // unavailable).  Fall back to HTTP/1.1 over the
                    // already-established TLS session.
                    const request_data = try http.formatRequest(req, self.allocator);
                    defer self.allocator.free(request_data);

                    try session.writeAll(request_data);
                    try session.flush();

                    return self.readResponseFromTLS(&session, req.method.hasResponseBody(), effective_policy.decompression);
                },
            }
        }

        var transport = SocketHTTP2Transport{ .socket = &socket };

        // Set recv timeout for the HTTP/2 preface exchange so we
        // do not hang if the server never responds.
        if (timeouts.read_ms > 0) {
            try socket.setRecvTimeout(timeouts.read_ms);
        }

        var h2_session = pool_mod.H2SessionState.init(self.allocator);
        defer h2_session.deinit();
        return self.executeHTTP2WithTransport(req, &transport, effective_policy.decompression, &h2_session);
    }

    fn executeRequestHTTP3(
        self: *Self,
        req: *Request,
        host: []const u8,
        port: u16,
        timeouts: RequestTimeouts,
        reqOpts: RequestOptions,
        effective_policy: *const types.EffectiveClientPolicy,
        context: *const IoContext,
    ) !Response {
        _ = reqOpts;
        const addr = try self.resolveAddress(host, port, context);

        var socket = try UdpSocket.createForAddress(addr);
        defer socket.close();

        if (timeouts.read_ms > 0) {
            try socket.setRecvTimeout(timeouts.read_ms);
        }
        if (timeouts.write_ms > 0) {
            try socket.setSendTimeout(timeouts.write_ms);
        }

        try socket.connect(addr);

        var transport = UDPHTTP3Transport{ .socket = &socket };
        return self.executeHTTP3WithTransport(req, &transport, effective_policy.decompression);
    }

    fn executeHTTP3WithTransport(
        self: *Self,
        req: *Request,
        transport: anytype,
        decompression: types.DecompressionPolicy,
    ) !Response {
        var qpack_encoder = qpack.QPACKContext.initWithCapacity(
            self.allocator,
            common.clampU64ToUsize(self.shared.config.http3_settings.qpack_max_table_capacity),
        );
        defer qpack_encoder.deinit();
        qpack_encoder.max_blocked_streams = self.shared.config.http3_settings.qpack_blocked_streams;

        var qpack_decoder = qpack.QPACKContext.initWithCapacity(
            self.allocator,
            common.clampU64ToUsize(self.shared.config.http3_settings.qpack_max_table_capacity),
        );
        defer qpack_decoder.deinit();
        qpack_decoder.max_blocked_streams = self.shared.config.http3_settings.qpack_blocked_streams;

        // HTTP/3 flow control state
        var conn_max_data: u64 = 10 * 1024 * 1024; // 10 MB default
        var conn_data_sent: u64 = 0;
        var stream_max_data: u64 = 1024 * 1024; // 1 MB default per stream
        var stream_data_sent: u64 = 0;

        var path_buf: ?[]u8 = null;
        defer if (path_buf) |buf| self.allocator.free(buf);
        var authority_buf: ?[]u8 = null;
        defer if (authority_buf) |buf| self.allocator.free(buf);

        var header_entries = std.ArrayList(qpack.HeaderEntry).empty;
        defer header_entries.deinit(self.allocator);

        var owned_header_names = std.ArrayList([]u8).empty;
        defer {
            for (owned_header_names.items) |name| self.allocator.free(name);
            owned_header_names.deinit(self.allocator);
        }

        try buildPseudoHeaders(self.allocator, req, &header_entries, &owned_header_names, &path_buf, &authority_buf);

        const headers_block = try qpack.encodeHeaders(&qpack_encoder, header_entries.items, self.allocator);
        defer self.allocator.free(headers_block);

        var request_stream_payload = std.ArrayList(u8).empty;
        defer request_stream_payload.deinit(self.allocator);
        try http.appendHTTP3Frame(&request_stream_payload, self.allocator, .headers, headers_block);

        if (req.body) |body| {
            if (body.len > 0) {
                // Check connection and stream flow control limits
                if (conn_data_sent + body.len > conn_max_data) return error.FlowControlError;
                if (stream_data_sent + body.len > stream_max_data) return error.FlowControlError;
                try http.appendHTTP3Frame(&request_stream_payload, self.allocator, .data, body);
                conn_data_sent += body.len;
                stream_data_sent += body.len;
            }
        }

        var settings_payload = std.ArrayList(u8).empty;
        defer settings_payload.deinit(self.allocator);
        try http.encodeHTTP3SettingsPayload(self.shared.config.http3_settings, self.allocator, &settings_payload);

        var control_stream_payload = std.ArrayList(u8).empty;
        defer control_stream_payload.deinit(self.allocator);
        try http.appendVarInt(&control_stream_payload, self.allocator, @intFromEnum(quic.HTTP3StreamType.control));
        try http.appendHTTP3Frame(&control_stream_payload, self.allocator, .settings, settings_payload.items);

        // Send MAX_DATA and MAX_STREAM_DATA to advertise our flow control limits
        {
            var max_data_payload = std.ArrayList(u8).empty;
            defer max_data_payload.deinit(self.allocator);
            try http.appendVarInt(&max_data_payload, self.allocator, conn_max_data);
            try http.appendHTTP3Frame(&control_stream_payload, self.allocator, .max_data, max_data_payload.items);
        }
        {
            var max_stream_data_payload = std.ArrayList(u8).empty;
            defer max_stream_data_payload.deinit(self.allocator);
            try http.appendVarInt(&max_stream_data_payload, self.allocator, 0); // stream_id 0
            try http.appendVarInt(&max_stream_data_payload, self.allocator, stream_max_data);
            try http.appendHTTP3Frame(&control_stream_payload, self.allocator, .max_stream_data, max_stream_data_payload.items);
        }

        var session = HTTP3QUICSession.initClient();

        // Client control stream (id=2) and request stream (id=0).
        try self.sendHTTP3StreamData(transport, &session, 2, false, control_stream_payload.items);
        try self.sendHTTP3StreamData(transport, &session, 0, true, request_stream_payload.items);

        var response_stream_payload = std.ArrayList(u8).empty;
        defer response_stream_payload.deinit(self.allocator);

        var peer_control_payload = std.ArrayList(u8).empty;
        defer peer_control_payload.deinit(self.allocator);

        var read_buf: [64 * 1024]u8 = undefined;
        var got_response_fin = false;

        var packet_counter: usize = 0;
        while (!got_response_fin) {
            packet_counter += 1;
            if (packet_counter > 10_000) return error.ProtocolError;

            const n = try transport.recvDatagram(&read_buf);
            if (n == 0) continue;

            const incoming = try decodeHTTP3StreamDatagram(read_buf[0..n], &session);

            if (incoming.stream_id == 0) {
                if (response_stream_payload.items.len + incoming.data.len > self.shared.config.max_response_size) {
                    return error.ResponseTooLarge;
                }
                try response_stream_payload.appendSlice(self.allocator, incoming.data);
                if (incoming.fin) {
                    got_response_fin = true;
                }
            } else if (incoming.stream_id == 3) {
                if (peer_control_payload.items.len + incoming.data.len > self.shared.config.max_response_size) {
                    return error.ResponseTooLarge;
                }
                try peer_control_payload.appendSlice(self.allocator, incoming.data);
            }
        }

        if (peer_control_payload.items.len > 0) {
            try parseHTTP3ControlStream(peer_control_payload.items);
        }

        var response_headers = Headers.init(self.allocator);
        defer response_headers.deinit();

        var response_body = std.ArrayList(u8).empty;
        defer response_body.deinit(self.allocator);

        var status_code: ?u16 = null;
        try self.parseHTTP3ResponseFrames(
            &qpack_decoder,
            response_stream_payload.items,
            &status_code,
            &response_headers,
            &response_body,
            &conn_max_data,
            &stream_max_data,
            &got_response_fin,
        );

        const final_status = status_code orelse return error.InvalidResponse;

        var response = Response.init(self.allocator, final_status);
        errdefer response.deinit();
        response.version = .HTTP_3;

        response.headers.deinit();
        response.headers = response_headers;
        response_headers = Headers.init(self.allocator);

        if (response_body.items.len > 0) {
            // Decompress body based on Content-Encoding header (HTTP/3).
            if (decompression == .enabled) {
                if (response.headers.get(HeaderName.CONTENT_ENCODING)) |encoding_str| {
                    if (compression_util.ContentEncoding.fromString(encoding_str)) |enc| {
                        if (enc != .identity) {
                            if (compression_util.decompress(self.allocator, enc, response_body.items)) |decompressed| {
                                response.body = decompressed;
                                response.body_owned = true;
                                return response;
                            } else |_| {}
                        }
                    }
                }
            }
            response.body = try response_body.toOwnedSlice(self.allocator);
            response.body_owned = true;
        }

        return response;
    }

    fn sendHTTP3StreamData(
        self: *Self,
        transport: anytype,
        session: *HTTP3QUICSession,
        stream_id: u64,
        fin: bool,
        payload: []const u8,
    ) !void {
        const max_chunk_size: usize = 1200;

        var offset: usize = 0;
        var sent_any = false;

        while (offset < payload.len or !sent_any) {
            const chunk_len = if (offset < payload.len)
                @min(max_chunk_size, payload.len - offset)
            else
                0;

            const chunk = payload[offset .. offset + chunk_len];
            const chunk_fin = fin and (offset + chunk_len == payload.len);

            const frame_storage = try self.allocator.alloc(u8, chunk_len + 64);
            defer self.allocator.free(frame_storage);

            const stream_frame = quic.StreamFrame{
                .stream_id = stream_id,
                .offset = @intCast(offset),
                .length = @intCast(chunk_len),
                .fin = chunk_fin,
                .data = chunk,
            };

            const frame_len = try stream_frame.encode(frame_storage);

            var packet = std.ArrayList(u8).empty;
            defer packet.deinit(self.allocator);

            try appendHTTP3PacketHeader(&packet, self.allocator, session);
            try packet.appendSlice(self.allocator, frame_storage[0..frame_len]);

            try transport.sendDatagram(packet.items);

            sent_any = true;
            offset += chunk_len;

            if (payload.len == 0) break;
        }
    }

    fn parseHTTP3ResponseFrames(
        self: *Self,
        qpack_decoder: *qpack.QPACKContext,
        payload: []const u8,
        status_code: *?u16,
        response_headers: *Headers,
        response_body: *std.ArrayList(u8),
        conn_max_data: *u64,
        stream_max_data: *u64,
        got_response_fin: *bool,
    ) !void {
        var offset: usize = 0;

        while (offset < payload.len) {
            const header_decoded = http.HTTP3FrameHeader.decode(payload[offset..]) catch return error.InvalidResponse;
            offset += header_decoded.len;

            const frame_len: usize = @intCast(header_decoded.header.length);
            if (payload.len < offset + frame_len) return error.InvalidResponse;

            const frame_payload = payload[offset .. offset + frame_len];
            offset += frame_len;

            switch (header_decoded.header.frame_type) {
                @intFromEnum(http.HTTP3FrameType.headers) => {
                    const decoded_headers = try qpack.decodeHeaders(qpack_decoder, frame_payload, self.allocator);
                    defer {
                        for (decoded_headers) |h| {
                            self.allocator.free(h.name);
                            self.allocator.free(h.value);
                        }
                        self.allocator.free(decoded_headers);
                    }

                    for (decoded_headers) |h| {
                        if (h.name.len > 0 and h.name[0] == ':') {
                            if (mem.eql(u8, h.name, ":status")) {
                                status_code.* = std.fmt.parseInt(u16, h.value, 10) catch return error.InvalidResponse;
                            }
                            continue;
                        }

                        if (common.isConnectionSpecificHeader(h.name)) continue;
                        try response_headers.append(h.name, h.value);
                    }
                },
                @intFromEnum(http.HTTP3FrameType.data) => {
                    if (response_body.items.len + frame_payload.len > self.shared.config.max_response_size) {
                        return error.ResponseTooLarge;
                    }
                    try response_body.appendSlice(self.allocator, frame_payload);
                },
                @intFromEnum(http.HTTP3FrameType.settings) => {
                    _ = try http.parseHTTP3SettingsPayload(frame_payload);
                },
                @intFromEnum(http.HTTP3FrameType.goaway) => {
                    // Gracefully handle GOAWAY: finish current stream processing
                    if (status_code.* != null) {
                        got_response_fin.* = true;
                    }
                },
                @intFromEnum(http.HTTP3FrameType.max_data) => {
                    if (frame_payload.len > 0) {
                        const val = try http.decodeVarInt(frame_payload);
                        conn_max_data.* = val.value;
                    }
                },
                @intFromEnum(http.HTTP3FrameType.max_stream_data) => {
                    if (frame_payload.len > 0) {
                        // stream_id varint + data_limit varint; update the relevant stream
                        const sid = try http.decodeVarInt(frame_payload);
                        const data_limit = try http.decodeVarInt(frame_payload[sid.len..]);
                        stream_max_data.* = data_limit.value;
                    }
                },
                else => {
                    // Unknown/unsupported frame types are ignored for forward compatibility.
                },
            }
        }
    }

    /// A frame buffered during the H2 body-upload flow-control pump phase.
    /// Freed by the caller after replaying in the response loop.
    const EarlyH2Frame = struct {
        header: http.HTTP2FrameHeader,
        payload: []u8,

        fn deinit(self: *EarlyH2Frame, allocator: Allocator) void {
            allocator.free(self.payload);
        }
    };

    /// A frame read by the H2 response loop -- wraps either a freshly-read frame
    /// (owned) or a replayed early frame (not owned by this value).
    const H2Frame = struct {
        header: http.HTTP2FrameHeader,
        payload: []u8,
        from_early_buf: bool,
    };

    fn applyHTTP2WindowUpdate(
        stream_manager: *h2stream.StreamManager,
        request_stream: *h2stream.Stream,
        header: http.HTTP2FrameHeader,
        payload: []const u8,
    ) !void {
        if (payload.len != 4) return error.ProtocolError;
        const increment_u32 = (@as(u32, payload[0] & 0x7F) << 24) |
            (@as(u32, payload[1]) << 16) |
            (@as(u32, payload[2]) << 8) |
            payload[3];
        if (increment_u32 == 0) return error.ProtocolError;
        const increment: i32 = @intCast(increment_u32);
        if (header.stream_id == 0) {
            try stream_manager.updateConnectionSendWindow(increment);
        } else if (header.stream_id == request_stream.id) {
            try request_stream.updateSendWindow(increment);
        }
    }

    fn applyHTTP2SettingsUpdate(
        transport: anytype,
        stream_manager: *h2stream.StreamManager,
        header: http.HTTP2FrameHeader,
        payload: []const u8,
        peer_max_frame_size: *u32,
    ) !void {
        if (header.stream_id != 0) return error.ProtocolError;
        const is_ack = (header.flags & 0x01) != 0;
        if (is_ack) {
            if (payload.len != 0) return error.ProtocolError;
            return;
        }

        var updated_settings = stream_manager.peer_settings;
        try http.applySettingsPayload(&updated_settings, payload);
        try stream_manager.applyPeerSettings(updated_settings);
        peer_max_frame_size.* = updated_settings.max_frame_size;
        try writeHTTP2Frame(transport, .settings, 0x01, 0, &.{});
    }

    fn parseHTTP2GoAway(self: *Client, header: http.HTTP2FrameHeader, payload: []const u8) !u31 {
        if (header.stream_id != 0) return error.ProtocolError;
        const goaway = h2stream.parseGoawayPayload(payload, self.allocator) catch
            return error.ProtocolError;
        defer if (goaway.debug_data) |debug_data| self.allocator.free(debug_data);
        return goaway.last_stream_id;
    }

    /// Pumps incoming HTTP/2 frames until the send window is positive.
    ///
    /// Called when `request_stream.send_window` or
    /// `stream_manager.connection_send_window` reaches zero mid-body upload.
    /// Processes WINDOW_UPDATE, SETTINGS, and PING frames to grow the send window.
    /// Early response frames (HEADERS/DATA/CONTINUATION) are appended to
    /// `early_frames` so the response loop can replay them without data loss.
    ///
    /// Returns `error.GoAway` if the server sends GOAWAY, or
    /// `error.StreamError` if the server resets the request stream.
    /// Returns `error.ProtocolError` if more than 10,000 frames are processed
    /// without the window being granted.
    fn pumpUntilSendWindow(
        self: *Client,
        transport: anytype,
        stream_manager: *h2stream.StreamManager,
        request_stream: *h2stream.Stream,
        peer_max_frame_size: *u32,
        early_frames: *std.ArrayList(EarlyH2Frame),
        session_state: *pool_mod.H2SessionState,
    ) !void {
        var pump_counter: usize = 0;
        while (request_stream.send_window <= 0 or stream_manager.connection_send_window <= 0) {
            pump_counter += 1;
            if (pump_counter > 10_000) return error.ProtocolError;

            var hdr_bytes: [9]u8 = undefined;
            try transport.readNoEof(&hdr_bytes);
            const fhdr = http.HTTP2FrameHeader.parse(hdr_bytes);

            const payload_len: usize = @intCast(fhdr.length);
            if (payload_len > self.shared.config.max_response_size) return error.FrameTooLarge;

            const payload = try self.allocator.alloc(u8, payload_len);
            if (payload_len > 0) {
                transport.readNoEof(payload) catch |err| {
                    self.allocator.free(payload);
                    return err;
                };
            }

            switch (fhdr.frame_type) {
                .window_update => {
                    applyHTTP2WindowUpdate(stream_manager, request_stream, fhdr, payload) catch |err| {
                        self.allocator.free(payload);
                        return err;
                    };
                    self.allocator.free(payload);
                },
                .settings => {
                    applyHTTP2SettingsUpdate(
                        transport,
                        stream_manager,
                        fhdr,
                        payload,
                        peer_max_frame_size,
                    ) catch |err| {
                        self.allocator.free(payload);
                        return err;
                    };
                    session_state.peer_max_frame_size = peer_max_frame_size.*;
                    self.allocator.free(payload);
                },
                .ping => {
                    if (fhdr.stream_id != 0 or payload.len != 8) {
                        self.allocator.free(payload);
                        return error.ProtocolError;
                    }
                    const is_ack = (fhdr.flags & 0x01) != 0;
                    if (!is_ack) {
                        writeHTTP2Frame(transport, .ping, 0x01, 0, payload) catch {
                            self.allocator.free(payload);
                            return error.WriteFailed;
                        };
                    }
                    self.allocator.free(payload);
                },
                .goaway => {
                    const last_stream_id = self.parseHTTP2GoAway(fhdr, payload) catch |err| {
                        self.allocator.free(payload);
                        return err;
                    };
                    session_state.draining = true;
                    self.allocator.free(payload);
                    if (request_stream.id > last_stream_id) return error.GoAway;
                },
                .rst_stream => {
                    if (fhdr.stream_id == request_stream.id) {
                        self.allocator.free(payload);
                        return error.StreamError;
                    }
                    self.allocator.free(payload);
                },
                .priority => {
                    self.allocator.free(payload);
                },
                .headers, .data, .continuation, .push_promise => {
                    // Early response frame -- buffer for replay in the response loop.
                    early_frames.append(self.allocator, .{
                        .header = fhdr,
                        .payload = payload,
                    }) catch |err| {
                        self.allocator.free(payload);
                        return err;
                    };
                },
                // RFC 7540 4.1: Unknown frame types MUST be ignored.
                _ => {
                    self.allocator.free(payload);
                },
            }
        }
    }

    fn executeHTTP2WithTransport(
        self: *Self,
        req: *Request,
        transport: anytype,
        decompression: types.DecompressionPolicy,
        session_state: *pool_mod.H2SessionState,
    ) !Response {
        const local_settings = toConnectionSettings(self.shared.config.http2_settings, self.shared.config.allow_push);
        if (!session_state.initialized) {
            try transport.writeAll(http.HTTP2_PREFACE);

            var settings_payload = std.ArrayList(u8).empty;
            defer settings_payload.deinit(self.allocator);
            try http.encodeSettingsPayload(local_settings, self.allocator, &settings_payload);
            try writeHTTP2Frame(transport, .settings, 0, 0, settings_payload.items);
            session_state.initialized = true;
        }

        const stream_manager = &session_state.stream_manager;
        const request_stream = try stream_manager.createStream();
        defer stream_manager.removeStream(request_stream.id);
        request_stream.send_window = @intCast(stream_manager.peer_settings.initial_window_size);
        try request_stream.open();

        var path_buf: ?[]u8 = null;
        defer if (path_buf) |buf| self.allocator.free(buf);
        var authority_buf: ?[]u8 = null;
        defer if (authority_buf) |buf| self.allocator.free(buf);

        var header_entries = std.ArrayList(hpack.HeaderEntry).empty;
        defer header_entries.deinit(self.allocator);

        var owned_header_names = std.ArrayList([]u8).empty;
        defer {
            for (owned_header_names.items) |name| self.allocator.free(name);
            owned_header_names.deinit(self.allocator);
        }

        try buildPseudoHeaders(self.allocator, req, &header_entries, &owned_header_names, &path_buf, &authority_buf);

        const has_body = req.body != null and req.body.?.len > 0;
        const headers_frames = try h2stream.buildHeadersAndContinuations(
            stream_manager,
            request_stream.id,
            header_entries.items,
            null,
            local_settings.max_frame_size,
            !has_body,
            self.allocator,
        );
        defer self.allocator.free(headers_frames);

        try transport.writeAll(headers_frames);

        var peer_max_frame_size: u32 = session_state.peer_max_frame_size;

        // Buffered early-response frames received during the body upload phase
        // (when we pump for WINDOW_UPDATE). These are replayed at the start of
        // the response loop so no frames are dropped.
        var early_frames = std.ArrayList(EarlyH2Frame).empty;
        defer {
            for (early_frames.items) |*ef| ef.deinit(self.allocator);
            early_frames.deinit(self.allocator);
        }

        if (has_body) {
            const body = req.body.?;
            var offset: usize = 0;
            while (offset < body.len) {
                // If either the stream or connection send window is exhausted,
                // pump incoming frames until we get enough WINDOW_UPDATE credit
                // rather than immediately failing with FlowControlError.
                if (request_stream.send_window <= 0 or stream_manager.connection_send_window <= 0) {
                    try pumpUntilSendWindow(
                        self,
                        transport,
                        stream_manager,
                        request_stream,
                        &peer_max_frame_size,
                        &early_frames,
                        session_state,
                    );
                }
                const window_stream = @as(i64, request_stream.send_window);
                const window_conn = @as(i64, stream_manager.connection_send_window);
                if (window_stream <= 0 or window_conn <= 0) return error.FlowControlError;
                const max_chunk = @min(
                    std.math.cast(usize, @as(u64, @intCast(window_stream))) orelse std.math.maxInt(usize),
                    std.math.cast(usize, @as(u64, @intCast(window_conn))) orelse std.math.maxInt(usize),
                );
                const chunk_len = @min(body.len - offset, max_chunk, @as(usize, @intCast(peer_max_frame_size)));
                const is_last = offset + chunk_len == body.len;
                const chunk_flags: u8 = if (is_last) 0x01 else 0;
                try writeHTTP2Frame(
                    transport,
                    .data,
                    chunk_flags,
                    request_stream.id,
                    body[offset .. offset + chunk_len],
                );
                request_stream.send_window -= @intCast(chunk_len);
                stream_manager.connection_send_window -= @intCast(chunk_len);
                offset += chunk_len;
            }
            request_stream.sendEndStream();
        } else {
            request_stream.sendEndStream();
        }

        var response_headers = Headers.init(self.allocator);
        defer response_headers.deinit();

        var trailers = Headers.init(self.allocator);
        defer trailers.deinit();

        var body = std.ArrayList(u8).empty;
        defer body.deinit(self.allocator);

        var pending_headers_block = std.ArrayList(u8).empty;
        defer pending_headers_block.deinit(self.allocator);

        var pending_headers_flags: u8 = 0;
        var waiting_continuation = false;

        var status_code: ?u16 = null;
        var response_done = false;
        var got_end_stream = false;

        // Replay buffered early-response frames collected during body upload
        // (pumpUntilSendWindow may have buffered them).  We process them first
        // so the loop below sees a logically complete frame stream.
        var early_frame_idx: usize = 0;

        var frame_counter: usize = 0;
        while (!response_done) {
            frame_counter += 1;
            if (frame_counter > 10_000) return error.ProtocolError;

            // Consume buffered early frames before reading from the transport.
            const frame: H2Frame = blk: {
                if (early_frame_idx < early_frames.items.len) {
                    const ef = &early_frames.items[early_frame_idx];
                    early_frame_idx += 1;
                    break :blk H2Frame{
                        .header = ef.header,
                        .payload = ef.payload,
                        .from_early_buf = true,
                    };
                }
                break :blk self.readHTTP2Frame(transport) catch |err| switch (err) {
                    error.UnexpectedEof => {
                        // RFC 7540 6.8: a server may close the connection
                        // after sending the final frame. If we already received a
                        // complete response (END_STREAM seen, status code present),
                        // treat the clean close as end-of-response rather than error.
                        if (got_end_stream and status_code != null) {
                            response_done = true;
                            continue;
                        }
                        return error.InvalidResponse;
                    },
                    else => return err,
                };
            };
            // Only free payload for frames we allocated ourselves (not early buf replays).
            defer if (!frame.from_early_buf) self.allocator.free(frame.payload);

            switch (frame.header.frame_type) {
                .settings => {
                    try applyHTTP2SettingsUpdate(
                        transport,
                        stream_manager,
                        frame.header,
                        frame.payload,
                        &peer_max_frame_size,
                    );
                    session_state.peer_max_frame_size = peer_max_frame_size;
                },
                .ping => {
                    if (frame.header.stream_id != 0) return error.ProtocolError;
                    const is_ack = (frame.header.flags & 0x01) != 0;
                    if (!is_ack) {
                        if (frame.payload.len != 8) return error.ProtocolError;
                        try writeHTTP2Frame(transport, .ping, 0x01, 0, frame.payload);
                    }
                },
                .goaway => {
                    const last_stream_id = try self.parseHTTP2GoAway(frame.header, frame.payload);
                    session_state.draining = true;
                    if (request_stream.id > last_stream_id) return error.GoAway;
                },
                .window_update => try applyHTTP2WindowUpdate(
                    stream_manager,
                    request_stream,
                    frame.header,
                    frame.payload,
                ),
                .priority => {},
                .push_promise => {
                    if (frame.header.stream_id == 0) return error.ProtocolError;
                    if (!self.shared.config.allow_push) {
                        const promised_stream_id = (@as(u31, frame.payload[0] & 0x7F) << 24) |
                            (@as(u31, frame.payload[1]) << 16) |
                            (@as(u31, frame.payload[2]) << 8) |
                            frame.payload[3];
                        const rst_frame = h2stream.buildRstStreamFrame(promised_stream_id, .refused_stream);
                        try transport.writeAll(&rst_frame);
                    }
                },
                .rst_stream => {
                    if (frame.header.stream_id == request_stream.id) {
                        if (!got_end_stream) {
                            const rst_frame = h2stream.buildRstStreamFrame(request_stream.id, .cancel);
                            try transport.writeAll(&rst_frame);
                            return error.StreamError;
                        }
                        response_done = true;
                    }
                },
                .headers => {
                    if (frame.header.stream_id != request_stream.id) continue;

                    if (got_end_stream) {
                        if (waiting_continuation) return error.ProtocolError;

                        if ((frame.header.flags & 0x04) != 0) {
                            const parsed = try h2stream.parseHeadersFramePayload(
                                stream_manager,
                                frame.payload,
                                frame.header.flags,
                                self.allocator,
                            );
                            defer {
                                for (parsed.headers) |header| {
                                    self.allocator.free(header.name);
                                    self.allocator.free(header.value);
                                }
                                self.allocator.free(parsed.headers);
                            }

                            for (parsed.headers) |header| {
                                if (header.name.len > 0 and header.name[0] == ':') continue;
                                if (common.isConnectionSpecificHeader(header.name)) continue;
                                try trailers.append(header.name, header.value);
                            }
                            response_done = true;
                        } else {
                            pending_headers_flags = frame.header.flags;
                            try pending_headers_block.appendSlice(self.allocator, frame.payload);
                            waiting_continuation = true;
                        }
                        continue;
                    }

                    if (waiting_continuation) return error.ProtocolError;

                    if ((frame.header.flags & 0x04) != 0) {
                        const expect_initial_headers = status_code == null;
                        try applyResponseHeaderBlock(
                            self,
                            stream_manager,
                            frame.payload,
                            frame.header.flags,
                            expect_initial_headers,
                            &status_code,
                            &response_headers,
                        );
                        if ((frame.header.flags & 0x01) != 0) {
                            got_end_stream = true;
                            request_stream.receiveEndStream();
                            // Fix: terminate the response loop immediately when
                            // END_STREAM is set on a HEADERS frame and we have
                            // a status code. Without this, the loop keeps
                            // reading frames from keep-alive servers until the
                            // recv timeout fires (causing a hang or ProtocolError).
                            if (status_code != null) response_done = true;
                        }
                    } else {
                        pending_headers_flags = frame.header.flags;
                        try pending_headers_block.appendSlice(self.allocator, frame.payload);
                        waiting_continuation = true;
                    }
                },
                .continuation => {
                    if (frame.header.stream_id != request_stream.id) continue;
                    if (!waiting_continuation) return error.ProtocolError;

                    try pending_headers_block.appendSlice(self.allocator, frame.payload);
                    if ((frame.header.flags & 0x04) != 0) {
                        if (got_end_stream) {
                            const parsed = try h2stream.parseHeadersFramePayload(
                                stream_manager,
                                pending_headers_block.items,
                                pending_headers_flags,
                                self.allocator,
                            );
                            defer {
                                for (parsed.headers) |header| {
                                    self.allocator.free(header.name);
                                    self.allocator.free(header.value);
                                }
                                self.allocator.free(parsed.headers);
                            }

                            for (parsed.headers) |header| {
                                if (header.name.len > 0 and header.name[0] == ':') continue;
                                if (common.isConnectionSpecificHeader(header.name)) continue;
                                try trailers.append(header.name, header.value);
                            }
                            pending_headers_block.clearRetainingCapacity();
                            waiting_continuation = false;
                            response_done = true;
                        } else {
                            const expect_initial_headers = status_code == null;
                            try applyResponseHeaderBlock(
                                self,
                                stream_manager,
                                pending_headers_block.items,
                                pending_headers_flags,
                                expect_initial_headers,
                                &status_code,
                                &response_headers,
                            );
                            pending_headers_block.clearRetainingCapacity();
                            waiting_continuation = false;

                            if ((pending_headers_flags & 0x01) != 0) {
                                got_end_stream = true;
                                request_stream.receiveEndStream();
                                // Fix: terminate on END_STREAM from CONTINUATION.
                                if (status_code != null) response_done = true;
                            }
                        }
                    }
                },
                .data => {
                    if (frame.header.stream_id != request_stream.id) continue;

                    if (got_end_stream) continue;

                    if (frame.header.length > local_settings.max_frame_size) return error.FrameTooLarge;

                    var data_slice = frame.payload;
                    if ((frame.header.flags & 0x08) != 0) {
                        if (frame.payload.len == 0) return error.ProtocolError;
                        const pad_len = frame.payload[0];
                        if (frame.payload.len < @as(usize, pad_len) + 1) return error.ProtocolError;
                        data_slice = frame.payload[1 .. frame.payload.len - pad_len];
                    }

                    if (body.items.len + data_slice.len > self.shared.config.max_response_size) return error.ResponseTooLarge;
                    try body.appendSlice(self.allocator, data_slice);

                    if (data_slice.len > 0) {
                        const window_increment: u31 = @intCast(data_slice.len);
                        const window_update = h2stream.buildWindowUpdatePayload(window_increment);
                        try writeHTTP2Frame(transport, .window_update, 0, request_stream.id, &window_update);
                        try writeHTTP2Frame(transport, .window_update, 0, 0, &window_update);
                    }

                    if ((frame.header.flags & 0x01) != 0) {
                        got_end_stream = true;
                        request_stream.receiveEndStream();
                        // Fix: terminate the response loop immediately when
                        // END_STREAM is set on a DATA frame and we have a
                        // status code. Without this, the loop keeps reading
                        // from keep-alive servers until the recv timeout fires.
                        if (status_code != null) response_done = true;
                    }
                },
                // RFC 7540 4.1: Unknown frame types MUST be ignored.
                _ => {},
            }
        }

        if (waiting_continuation) return error.InvalidResponse;

        const final_status = status_code orelse return error.InvalidResponse;

        var response = Response.init(self.allocator, final_status);
        errdefer response.deinit();
        response.version = .HTTP_2;

        response.headers.deinit();
        response.headers = response_headers;
        response_headers = Headers.init(self.allocator);

        if (trailers.count() > 0) {
            response.trailers = trailers;
            trailers = Headers.init(self.allocator);
        }

        if (body.items.len > 0) {
            // Decompress body based on Content-Encoding header (HTTP/2).
            if (decompression == .enabled) {
                if (response.headers.get(HeaderName.CONTENT_ENCODING)) |encoding_str| {
                    if (compression_util.ContentEncoding.fromString(encoding_str)) |enc| {
                        if (enc != .identity) {
                            if (compression_util.decompress(self.allocator, enc, body.items)) |decompressed| {
                                response.body = decompressed;
                                response.body_owned = true;
                                return response;
                            } else |_| {}
                        }
                    }
                }
            }
            response.body = try body.toOwnedSlice(self.allocator);
            response.body_owned = true;
        }

        return response;
    }

    fn readHTTP2Frame(self: *Self, transport: anytype) !H2Frame {
        var header_bytes: [9]u8 = undefined;
        try transport.readNoEof(&header_bytes);
        const header = http.HTTP2FrameHeader.parse(header_bytes);

        const payload_len: usize = @intCast(header.length);
        if (payload_len > self.shared.config.max_response_size) return error.FrameTooLarge;

        const payload = try self.allocator.alloc(u8, payload_len);
        errdefer self.allocator.free(payload);

        if (payload_len > 0) {
            try transport.readNoEof(payload);
        }

        return .{ .header = header, .payload = payload, .from_early_buf = false };
    }

    /// Context for TLS version fallback reconnection.
    /// When TLS 1.3 fails and the server closes the TCP connection,
    /// the reconnect callback creates a fresh socket for the TLS 1.2 retry.
    const ReconnectContext = struct {
        allocator: Allocator,
        host: []const u8,
        port: u16,
        socket: ?*Socket = null,
    };

    fn reconnectCallback(ctx_ptr: ?*anyopaque) ?*Socket {
        const ctx: *ReconnectContext = @ptrCast(@alignCast(ctx_ptr.?));
        // Resolve address first to create the correct socket family (IPv4/IPv6).
        const addr = address_mod.resolve(ctx.allocator, ctx.host, ctx.port) catch return null;
        const socket = ctx.allocator.create(Socket) catch return null;
        socket.* = Socket.createForAddress(addr) catch {
            ctx.allocator.destroy(socket);
            return null;
        };
        socket.connect(addr) catch {
            socket.close();
            ctx.allocator.destroy(socket);
            return null;
        };
        socket.setNoDelay(true) catch {};
        ctx.socket = socket;
        return socket;
    }

    fn handshakePooledTls(
        self: *Self,
        lease: *ConnectionLease,
        session: *TLSSession,
        host: []const u8,
        port: u16,
        allow_reconnect: bool,
    ) !void {
        var reconnect_ctx = ReconnectContext{
            .allocator = self.allocator,
            .host = host,
            .port = port,
        };
        errdefer if (reconnect_ctx.socket) |socket| {
            socket.close();
            self.allocator.destroy(socket);
        };

        if (allow_reconnect) {
            session.reconnect_fn = reconnectCallback;
            session.reconnect_ctx = &reconnect_ctx;
        }
        defer {
            session.reconnect_fn = null;
            session.reconnect_ctx = null;
        }

        try session.handshake(host);
        if (reconnect_ctx.socket) |socket| {
            const replacement = socket.*;
            self.allocator.destroy(socket);
            reconnect_ctx.socket = null;
            lease.replaceSocket(replacement);
        }
    }

    fn executeTLSHttp(
        self: *Self,
        socket: *Socket,
        host: []const u8,
        port: u16,
        request_data: []const u8,
        verify_ssl: bool,
        decompression: types.DecompressionPolicy,
    ) !Response {
        const tls_cfg = if (verify_ssl) TLSConfig.init(self.allocator) else TLSConfig.insecure(self.allocator);

        // Set up reconnect context for TLS version fallback.
        // When TLS 1.3 fails and the server closes the connection,
        // we need a fresh TCP socket for the TLS 1.2 retry.
        var reconnect_ctx = ReconnectContext{
            .allocator = self.allocator,
            .host = host,
            .port = port,
            .socket = null,
        };
        // Ensure reconnect socket is cleaned up on any error
        errdefer if (reconnect_ctx.socket) |s| {
            s.close();
            self.allocator.destroy(s);
        };

        var session = TLSSession.init(tls_cfg);
        defer session.deinit();
        session.attachSocket(socket);
        session.reconnect_fn = reconnectCallback;
        session.reconnect_ctx = &reconnect_ctx;
        try session.handshake(host);

        // Use encrypted write/read (TLS record layer)
        try session.writeAll(request_data);
        try session.flush();

        var buf: [16 * 1024]u8 = undefined;
        var total_read: usize = 0;
        var parser = Parser.initResponse(self.allocator);
        defer parser.deinit();

        while (!parser.isComplete()) {
            const n = try session.read(&buf);
            if (n == 0) break;
            total_read += n;
            if (total_read > self.shared.config.max_response_size) return error.ResponseTooLarge;
            _ = try parser.feed(buf[0..n]);
        }

        parser.finishEof();
        if (!parser.isComplete()) return error.InvalidResponse;

        // Clean up reconnect socket if it was allocated.
        // The caller's `defer socket.close()` handles the original socket.
        // session.deinit() does not close the socket, so we must clean up
        // any heap-allocated reconnect socket here.
        if (reconnect_ctx.socket) |s| {
            s.close();
            self.allocator.destroy(s);
        }

        return responseFromParser(&parser, decompression);
    }

    fn readResponseFromReadFn(
        self: *Self,
        reader: anytype,
        readFn: *const fn (@TypeOf(reader), []u8) anyerror!usize,
        expect_body: bool,
        decompression: types.DecompressionPolicy,
    ) !Response {
        var parser = Parser.initResponse(self.allocator);
        defer parser.deinit();
        parser.expect_body = expect_body;

        var buf: [16 * 1024]u8 = undefined;
        var total_read: usize = 0;
        while (!parser.isComplete()) {
            const n = try readFn(reader, &buf);
            if (n == 0) break;
            total_read += n;
            if (total_read > self.shared.config.max_response_size) return error.ResponseTooLarge;
            _ = try parser.feed(buf[0..n]);
        }

        parser.finishEof();

        if (!parser.isComplete()) return error.InvalidResponse;
        return responseFromParser(&parser, decompression);
    }

    fn readResponseFromTcp(
        self: *Self,
        socket: *Socket,
        expect_body: bool,
        decompression: types.DecompressionPolicy,
    ) !Response {
        return self.readResponseFromReadFn(socket, Socket.recv, expect_body, decompression);
    }

    fn readResponseFromTLS(
        self: *Self,
        session: *TLSSession,
        expect_body: bool,
        decompression: types.DecompressionPolicy,
    ) !Response {
        return self.readResponseFromReadFn(session, TLSSession.read, expect_body, decompression);
    }

    fn readResponseFromIo(self: *Self, r: *std.Io.Reader, decompression: types.DecompressionPolicy) !Response {
        var parser = Parser.initResponse(self.allocator);
        defer parser.deinit();

        var total_read: usize = 0;
        while (!parser.isComplete()) {
            const buffered = r.buffered();
            if (buffered.len == 0) {
                r.fillMore() catch |err| switch (err) {
                    error.EndOfStream => break,
                    error.ReadFailed => return error.ReadFailed,
                };
                continue;
            }
            total_read += buffered.len;
            if (total_read > self.shared.config.max_response_size) return error.ResponseTooLarge;
            const consumed = try parser.feed(buffered);
            r.toss(consumed);
        }

        parser.finishEof();

        if (!parser.isComplete()) return error.InvalidResponse;
        return responseFromParser(&parser, decompression);
    }

    fn responseFromParser(parser: *Parser, decompression: types.DecompressionPolicy) !Response {
        const code = parser.status_code orelse return error.InvalidResponse;
        var res = Response.init(parser.allocator, code);
        errdefer res.deinit();
        res.version = parser.version;

        // Move headers ownership from parser to response.
        res.headers.deinit();
        res.headers = parser.headers;
        parser.headers = Headers.init(parser.allocator);

        if (parser.getBody().len > 0) {
            const raw_body = parser.getBody();
            if (decompression == .enabled) {
                if (res.headers.get(HeaderName.CONTENT_ENCODING)) |encoding_str| {
                    if (compression_util.ContentEncoding.fromString(encoding_str)) |enc| {
                        if (enc != .identity) {
                            const decompressed = compression_util.decompress(parser.allocator, enc, raw_body) catch |err| {
                                return err;
                            };
                            res.body = decompressed;
                            res.body_owned = true;
                            return res;
                        }
                    }
                }
            }
            res.body = try parser.allocator.dupe(u8, raw_body);
            res.body_owned = true;
        }

        return res;
    }

    fn responseIsReusable(response: *const Response, expect_body: bool) bool {
        if (!response.headers.isKeepAlive(response.version)) return false;
        if (!expect_body or
            (response.status.code >= 100 and response.status.code < 200) or
            response.status.code == 204 or
            response.status.code == 304)
        {
            return true;
        }
        return response.headers.getContentLength() != null or response.headers.isChunked();
    }

    fn resolveRedirectUrl(self: *Self, base: Uri, location: []const u8) ![]u8 {
        // Absolute URL.
        if (mem.indexOf(u8, location, "://") != null) {
            return self.allocator.dupe(u8, location);
        }

        // Protocol-relative URL: //httpbun.com/path
        if (location.len > 1 and location[0] == '/' and location[1] == '/') {
            const scheme = base.scheme orelse "http";
            return std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ scheme, location });
        }

        const scheme = base.scheme orelse "http";
        const host = base.host orelse return error.InvalidUri;
        const port = base.effectivePort();

        if (location.len > 0 and location[0] == '/') {
            return std.fmt.allocPrint(self.allocator, "{s}://{s}:{d}{s}", .{ scheme, host, port, location });
        }

        // Relative to current path.
        const base_path = base.path;
        const slash = mem.lastIndexOfScalar(u8, base_path, '/') orelse 0;
        const prefix = base_path[0 .. slash + 1];
        return std.fmt.allocPrint(self.allocator, "{s}://{s}:{d}{s}{s}", .{ scheme, host, port, prefix, location });
    }

    /// Returns true if two URLs share the same origin (scheme + host + port).
    fn isSameOrigin(base_url: []const u8, target_url: []const u8) bool {
        const base_host = extractOriginHost(base_url) orelse return false;
        const target_host = extractOriginHost(target_url) orelse return false;
        return std.ascii.eqlIgnoreCase(base_host, target_host);
    }

    fn extractOriginHost(url: []const u8) ?[]const u8 {
        var rest = url;
        if (mem.startsWith(u8, rest, "https://")) {
            rest = rest[8..];
        } else if (mem.startsWith(u8, rest, "http://")) {
            rest = rest[7..];
        } else {
            return null;
        }
        const host_end = mem.indexOfAny(u8, rest, "/:?#@") orelse rest.len;
        return if (host_end > 0) rest[0..host_end] else null;
    }

    fn attachCookies(self: *Self, req: *Request) !void {
        // A caller-provided Cookie header is authoritative.
        if (req.headers.contains(HeaderName.COOKIE)) return;
        ClientState.lock(&self.shared.cookie_lock);
        defer self.shared.cookie_lock.unlock();
        if (self.shared.cookies.count() == 0) return;

        const req_host = req.uri.host orelse return;
        const req_path = if (req.uri.path.len > 0) req.uri.path else "/";
        const req_is_tls = req.uri.isTLS();
        const now = std.Io.Timestamp.now(io_util.defaultIo(), .real).toSeconds();

        var list = std.ArrayList(u8).empty;
        defer list.deinit(self.allocator);
        const writer = list_writer.init(self.allocator, &list);

        var it = self.shared.cookies.iterator();
        var first = true;
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            const cookie = entry.value_ptr.*;
            // Cookie keys are stored as "domain|name" for domain-aware storage.
            if (mem.lastIndexOfScalar(u8, name, '|')) |pipe| {
                const cookie_domain = name[0..pipe];
                const cookie_name = name[pipe + 1 ..];
                // Domain matching
                if (!domainMatches(req_host, cookie_domain)) continue;
                // Path matching: cookie path must be a prefix of the request path
                if (!pathMatches(req_path, cookie.path)) continue;
                // Secure flag: only send over HTTPS
                if (cookie.secure and !req_is_tls) continue;
                // Max-Age expiry: skip expired cookies
                if (cookie.max_age) |max_age| {
                    if (max_age > 0) {
                        const elapsed = now - cookie.stored_at;
                        if (elapsed > max_age) continue;
                    }
                }
                if (!first) try writer.writeAll("; ");
                first = false;
                try writer.print("{s}={s}", .{ cookie_name, cookie.value });
            } else {
                // Legacy cookie without domain - send to all hosts
                if (!first) try writer.writeAll("; ");
                first = false;
                try writer.print("{s}={s}", .{ name, cookie.value });
            }
        }

        if (list.items.len > 0) {
            try req.headers.set(HeaderName.COOKIE, list.items);
        }
    }

    /// Returns true if `host` matches `cookie_domain`.
    /// A cookie with domain ".httpbun.com" matches "www.httpbun.com" and "httpbun.com".
    fn domainMatches(host: []const u8, cookie_domain: []const u8) bool {
        // Exact match
        if (std.mem.eql(u8, host, cookie_domain)) return true;
        // Subdomain match: host must end with "." + cookie_domain
        if (cookie_domain.len > 0 and cookie_domain[0] == '.') {
            return std.mem.endsWith(u8, host, cookie_domain);
        }
        // Implicit dot: "httpbun.com" matches "www.httpbun.com"
        if (host.len > cookie_domain.len + 1) {
            const suffix = host[host.len - cookie_domain.len ..];
            if (std.mem.eql(u8, suffix, cookie_domain)) {
                return host[host.len - cookie_domain.len - 1] == '.';
            }
        }
        return false;
    }

    /// Returns true if `req_path` matches the cookie's `path` attribute.
    /// RFC 6265 Section 5.1.4: cookie path matching.
    fn pathMatches(req_path: []const u8, cookie_path: []const u8) bool {
        // Exact match
        if (mem.eql(u8, req_path, cookie_path)) return true;
        // The cookie path must be a prefix of the request path
        if (!mem.startsWith(u8, req_path, cookie_path)) return false;
        // If the cookie path ends with '/', it's a prefix match
        if (cookie_path.len > 0 and cookie_path[cookie_path.len - 1] == '/') return true;
        // Otherwise, the first character after the prefix must be '/'
        if (req_path.len > cookie_path.len) return req_path[cookie_path.len] == '/';
        return false;
    }

    fn storeCookies(self: *Self, res: *const Response, request_host: []const u8) !void {
        const values = try res.headers.getAll(HeaderName.SET_COOKIE, self.allocator);
        defer self.allocator.free(values);

        const now = std.Io.Timestamp.now(io_util.defaultIo(), .real).toSeconds();
        ClientState.lock(&self.shared.cookie_lock);
        defer self.shared.cookie_lock.unlock();

        for (values) |set_cookie| {
            const parsed = common.parseSetCookie(set_cookie) orelse continue;
            if (self.shared.config.max_cookie_size > 0 and (parsed.name.len + parsed.value.len) > self.shared.config.max_cookie_size) continue;
            if (self.shared.config.max_cookies > 0 and self.shared.cookies.count() >= self.shared.config.max_cookies) break;
            try self.storeCookieLocked(parsed, request_host, now);
        }
    }

    fn storeCookieLocked(self: *Self, parsed: common.ParsedCookie, request_host: []const u8, now: i64) !void {
        const domain = parsed.domain orelse request_host;
        const key = try std.fmt.allocPrint(self.allocator, "{s}|{s}", .{ domain, parsed.name });
        errdefer self.allocator.free(key);
        const owned_value = try self.allocator.dupe(u8, parsed.value);
        errdefer self.allocator.free(owned_value);
        const owned_path = try self.allocator.dupe(u8, parsed.path orelse "/");
        errdefer self.allocator.free(owned_path);
        const owned_domain = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(owned_domain);

        if (self.shared.cookies.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            freeCookieEntry(self.allocator, removed.value);
        }
        try self.shared.cookies.put(self.allocator, key, .{
            .value = owned_value,
            .path = owned_path,
            .domain = owned_domain,
            .secure = parsed.secure,
            .http_only = parsed.http_only,
            .same_site = parsed.same_site,
            .max_age = parsed.max_age,
            .stored_at = now,
        });
    }

    /// Adds or replaces a cookie in the in-memory client cookie jar.
    /// The cookie is stored with domain association using "domain|name" format.
    pub fn setCookie(self: *Self, name: []const u8, value: []const u8) !void {
        ClientState.lock(&self.shared.cookie_lock);
        defer self.shared.cookie_lock.unlock();
        // If name already contains a domain prefix, use it as-is
        const key = if (mem.lastIndexOfScalar(u8, name, '|') != null)
            name
        else
            name; // Legacy: no domain, matches all hosts

        if (self.shared.cookies.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            freeCookieEntry(self.allocator, removed.value);
        }

        const owned_name = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_name);
        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);
        const owned_path = try self.allocator.dupe(u8, "/");
        errdefer self.allocator.free(owned_path);
        const owned_domain = try self.allocator.dupe(u8, "");
        errdefer self.allocator.free(owned_domain);

        try self.shared.cookies.put(self.allocator, owned_name, .{
            .value = owned_value,
            .path = owned_path,
            .domain = owned_domain,
        });
    }

    /// Adds or replaces a cookie with explicit domain association.
    pub fn setCookieWithDomain(self: *Self, name: []const u8, value: []const u8, domain: []const u8) !void {
        ClientState.lock(&self.shared.cookie_lock);
        defer self.shared.cookie_lock.unlock();
        const key = try std.fmt.allocPrint(self.allocator, "{s}|{s}", .{ domain, name });
        errdefer self.allocator.free(key);

        if (self.shared.cookies.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            freeCookieEntry(self.allocator, removed.value);
        }

        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);
        const owned_path = try self.allocator.dupe(u8, "/");
        errdefer self.allocator.free(owned_path);
        const owned_domain = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(owned_domain);

        try self.shared.cookies.put(self.allocator, key, .{
            .value = owned_value,
            .path = owned_path,
            .domain = owned_domain,
        });
    }

    /// Returns an owned cookie value safe from concurrent jar mutation.
    pub fn getCookie(self: *const Self, name: []const u8) !?[]u8 {
        ClientState.lock(&self.shared.cookie_lock);
        defer self.shared.cookie_lock.unlock();
        if (self.shared.cookies.get(name)) |entry| return try self.allocator.dupe(u8, entry.value);
        return null;
    }

    pub fn freeCookieValue(self: *const Self, value: []u8) void {
        self.allocator.free(value);
    }

    /// Removes a cookie from the in-memory cookie jar.
    pub fn removeCookie(self: *Self, name: []const u8) bool {
        ClientState.lock(&self.shared.cookie_lock);
        defer self.shared.cookie_lock.unlock();
        if (self.shared.cookies.fetchRemove(name)) |removed| {
            self.allocator.free(removed.key);
            freeCookieEntry(self.allocator, removed.value);
            return true;
        }
        return false;
    }

    /// Clears all cookies from the in-memory cookie jar.
    pub fn clearCookies(self: *Self) void {
        ClientState.lock(&self.shared.cookie_lock);
        defer self.shared.cookie_lock.unlock();
        var it = self.shared.cookies.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            freeCookieEntry(self.allocator, entry.value_ptr.*);
        }
        self.shared.cookies.clearRetainingCapacity();
    }

    /// Returns true if a cookie with the given name exists in the jar.
    pub fn hasCookie(self: *const Self, name: []const u8) bool {
        ClientState.lock(&self.shared.cookie_lock);
        defer self.shared.cookie_lock.unlock();
        return self.shared.cookies.contains(name);
    }

    /// Returns the number of cookies currently stored in the jar.
    pub fn cookieCount(self: *const Self) usize {
        ClientState.lock(&self.shared.cookie_lock);
        defer self.shared.cookie_lock.unlock();
        return self.shared.cookies.count();
    }

    /// Removes all expired cookies from the jar.
    pub fn pruneExpiredCookies(self: *Self) void {
        ClientState.lock(&self.shared.cookie_lock);
        defer self.shared.cookie_lock.unlock();
        const now = std.Io.Timestamp.now(io_util.defaultIo(), .real).toSeconds();
        var to_remove = std.ArrayList([]const u8).empty;
        defer to_remove.deinit(self.allocator);

        var it = self.shared.cookies.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.max_age) |max_age| {
                if (max_age > 0) {
                    const elapsed = now - entry.value_ptr.*.stored_at;
                    if (elapsed > max_age) {
                        to_remove.append(self.allocator, entry.key_ptr.*) catch {};
                    }
                }
            }
        }
        for (to_remove.items) |key| {
            if (self.shared.cookies.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
                freeCookieEntry(self.allocator, removed.value);
            }
        }
    }

    /// GET request convenience method.
    pub fn get(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.GET, url, reqOpts);
    }

    /// POST request convenience method.
    pub fn post(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.POST, url, reqOpts);
    }

    /// PUT request convenience method.
    pub fn put(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.PUT, url, reqOpts);
    }

    /// DELETE request convenience method.
    pub fn delete(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.DELETE, url, reqOpts);
    }

    /// Alias for delete() with short method naming.
    pub fn del(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.delete(url, reqOpts);
    }

    /// PATCH request convenience method.
    pub fn patch(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.PATCH, url, reqOpts);
    }

    /// HEAD request convenience method.
    pub fn head(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.HEAD, url, reqOpts);
    }

    /// TRACE request convenience method.
    pub fn trace(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.TRACE, url, reqOpts);
    }

    /// CONNECT request convenience method.
    pub fn connect(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.CONNECT, url, reqOpts);
    }

    /// OPTIONS request convenience method.
    pub fn options(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.OPTIONS, url, reqOpts);
    }

    /// Alias for options() with short method naming.
    pub fn opts(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.options(url, reqOpts);
    }

    /// GET request that parses the JSON response into type T.
    /// Returns both the response and parsed value. Caller deinit's both.
    pub fn getJson(self: *Self, comptime T: type, url: []const u8, parse_opts: std.json.ParseOptions) !JsonBorrowedResult(T) {
        const response = try self.get(url, .{ .headers = &.{.{ "Accept", "application/json" }} });
        const value = try response.jsonBorrowed(T, parse_opts);
        return .{ .response = response, .value = value };
    }

    /// GET request with zero-copy JSON parse. Returns both the response and
    /// parsed value. The response must outlive the parsed value.
    pub fn getJsonBorrowed(self: *Self, comptime T: type, url: []const u8) !JsonBorrowedResult(T) {
        const response = try self.get(url, .{ .headers = &.{.{ "Accept", "application/json" }} });
        const value = try response.jsonBorrowed(T, .{});
        return .{ .response = response, .value = value };
    }

    /// POST JSON body and parse the response as type T.
    /// Returns both the response and parsed value. Caller deinit's both.
    pub fn postJsonAndParse(self: *Self, comptime T: type, url: []const u8, body: []const u8, parse_opts: std.json.ParseOptions) !JsonBorrowedResult(T) {
        const response = try self.post(url, .{ .json = body });
        const value = try response.jsonBorrowed(T, parse_opts);
        return .{ .response = response, .value = value };
    }

    /// POST JSON body with zero-copy parse. Caller must keep response alive.
    pub fn postJsonBorrowed(self: *Self, comptime T: type, url: []const u8, body: []const u8) !JsonBorrowedResult(T) {
        const response = try self.post(url, .{ .json = body });
        const value = try response.jsonBorrowed(T, .{});
        return .{ .response = response, .value = value };
    }

    /// PUT JSON body and parse the response as type T.
    /// Returns both the response and parsed value. Caller deinit's both.
    pub fn putJson(self: *Self, comptime T: type, url: []const u8, body: []const u8, parse_opts: std.json.ParseOptions) !JsonBorrowedResult(T) {
        const response = try self.put(url, .{ .json = body });
        const value = try response.jsonBorrowed(T, parse_opts);
        return .{ .response = response, .value = value };
    }

    /// PUT JSON body with zero-copy parse.
    pub fn putJsonBorrowed(self: *Self, comptime T: type, url: []const u8, body: []const u8) !JsonBorrowedResult(T) {
        const response = try self.put(url, .{ .json = body });
        const value = try response.jsonBorrowed(T, .{});
        return .{ .response = response, .value = value };
    }

    /// PATCH JSON body and parse the response as type T.
    /// Returns both the response and parsed value. Caller deinit's both.
    pub fn patchJson(self: *Self, comptime T: type, url: []const u8, body: []const u8, parse_opts: std.json.ParseOptions) !JsonBorrowedResult(T) {
        const response = try self.patch(url, .{ .json = body });
        const value = try response.jsonBorrowed(T, parse_opts);
        return .{ .response = response, .value = value };
    }

    /// PATCH JSON body with zero-copy parse.
    pub fn patchJsonBorrowed(self: *Self, comptime T: type, url: []const u8, body: []const u8) !JsonBorrowedResult(T) {
        const response = try self.patch(url, .{ .json = body });
        const value = try response.jsonBorrowed(T, .{});
        return .{ .response = response, .value = value };
    }

    /// DELETE request that parses the JSON response as type T.
    /// Returns both the response and parsed value. Caller deinit's both.
    pub fn deleteJson(self: *Self, comptime T: type, url: []const u8, parse_opts: std.json.ParseOptions) !JsonBorrowedResult(T) {
        const response = try self.delete(url, .{ .headers = &.{.{ "Accept", "application/json" }} });
        const value = try response.jsonBorrowed(T, parse_opts);
        return .{ .response = response, .value = value };
    }

    /// DELETE request with zero-copy JSON parse.
    pub fn deleteJsonBorrowed(self: *Self, comptime T: type, url: []const u8) !JsonBorrowedResult(T) {
        const response = try self.delete(url, .{ .headers = &.{.{ "Accept", "application/json" }} });
        const value = try response.jsonBorrowed(T, .{});
        return .{ .response = response, .value = value };
    }
};

/// Result of a zero-copy JSON parse. Holds both the response (which owns the
/// body buffer) and the parsed value (which borrows string slices from it).
/// The caller must keep `response` alive while using `value`, then deinit both.
pub fn JsonBorrowedResult(comptime T: type) type {
    return struct {
        response: Response,
        value: T,
    };
}

const SocketHTTP2Transport = struct {
    socket: *Socket,

    fn writeAll(self: *SocketHTTP2Transport, data: []const u8) !void {
        try self.socket.sendAll(data);
    }

    fn readNoEof(self: *SocketHTTP2Transport, out: []u8) !void {
        var read: usize = 0;
        while (read < out.len) {
            const n = try self.socket.recv(out[read..]);
            if (n == 0) return error.UnexpectedEof;
            read += n;
        }
    }
};

const TLSHTTP2Transport = struct {
    session: *TLSSession,

    fn writeAll(self: *TLSHTTP2Transport, data: []const u8) !void {
        try self.session.writeAll(data);
        try self.session.flush();
    }

    fn readNoEof(self: *TLSHTTP2Transport, out: []u8) !void {
        var read: usize = 0;
        while (read < out.len) {
            const n = try self.session.read(out[read..]);
            if (n == 0) return error.UnexpectedEof;
            read += n;
        }
    }
};

const UDPHTTP3Transport = struct {
    socket: *UdpSocket,

    fn sendDatagram(self: *UDPHTTP3Transport, data: []const u8) !void {
        const sent = try self.socket.send(data);
        if (sent != data.len) return error.ShortWrite;
    }

    fn recvDatagram(self: *UDPHTTP3Transport, out: []u8) !usize {
        return self.socket.recv(out);
    }
};

const HTTP3QUICSession = struct {
    local_cid: quic.ConnectionId,
    peer_cid: quic.ConnectionId,
    next_packet_number: u64 = 0,
    sent_initial: bool = false,

    fn initClient() HTTP3QUICSession {
        return .{
            .local_cid = quic.ConnectionId.random(),
            .peer_cid = quic.ConnectionId.random(),
        };
    }
};

/// Sends a QUIC RESET_STREAM frame to cancel a stream.
fn sendHTTP3ResetStream(
    transport: anytype,
    session: *HTTP3QUICSession,
    stream_id: u64,
    error_code: u64,
    final_size: u64,
    allocator: Allocator,
) !void {
    var frame_buf: [64]u8 = undefined;
    const frame = quic.ResetStreamFrame{
        .stream_id = stream_id,
        .error_code = error_code,
        .final_size = final_size,
    };
    const frame_len = try frame.encode(&frame_buf);

    var packet = std.ArrayList(u8).empty;
    defer packet.deinit(allocator);

    try appendHTTP3PacketHeader(&packet, allocator, session);
    try packet.appendSlice(allocator, frame_buf[0..frame_len]);

    try transport.sendDatagram(packet.items);
}

/// Sends a QUIC STOP_SENDING frame to tell the peer to stop sending on a stream.
fn sendHTTP3StopSending(
    transport: anytype,
    session: *HTTP3QUICSession,
    stream_id: u64,
    error_code: u64,
    allocator: Allocator,
) !void {
    var frame_buf: [64]u8 = undefined;
    const frame = quic.StopSendingFrame{
        .stream_id = stream_id,
        .error_code = error_code,
    };
    const frame_len = try frame.encode(&frame_buf);

    var packet = std.ArrayList(u8).empty;
    defer packet.deinit(allocator);

    try appendHTTP3PacketHeader(&packet, allocator, session);
    try packet.appendSlice(allocator, frame_buf[0..frame_len]);

    try transport.sendDatagram(packet.items);
}

const DecodedHTTP3StreamDatagram = struct {
    stream_id: u64,
    fin: bool,
    data: []const u8,
};

fn parseHTTP3ControlStream(stream_data: []const u8) !void {
    if (stream_data.len == 0) return error.ProtocolError;

    var offset: usize = 0;
    const stream_type = try http.decodeVarInt(stream_data[offset..]);
    offset += stream_type.len;

    if (stream_type.value != @intFromEnum(quic.HTTP3StreamType.control)) {
        return error.ProtocolError;
    }

    var saw_settings = false;

    while (offset < stream_data.len) {
        const frame = http.HTTP3FrameHeader.decode(stream_data[offset..]) catch return error.ProtocolError;
        offset += frame.len;

        const payload_len: usize = @intCast(frame.header.length);
        if (stream_data.len < offset + payload_len) return error.ProtocolError;

        const payload = stream_data[offset .. offset + payload_len];
        offset += payload_len;

        if (frame.header.frame_type == @intFromEnum(http.HTTP3FrameType.settings)) {
            _ = try http.parseHTTP3SettingsPayload(payload);
            saw_settings = true;
        }
    }

    if (!saw_settings) return error.ProtocolError;
}

fn appendHTTP3PacketHeader(
    out: *std.ArrayList(u8),
    allocator: Allocator,
    session: *HTTP3QUICSession,
) !void {
    var hdr_buf: [128]u8 = undefined;

    const hdr_len = if (!session.sent_initial) blk: {
        const long_header = quic.LongHeader{
            .packet_type = .initial,
            .version = .v1,
            .dcid = session.peer_cid,
            .scid = session.local_cid,
        };
        const n = try long_header.encode(&hdr_buf);
        session.sent_initial = true;
        break :blk n;
    } else blk: {
        const short_header = quic.ShortHeader{ .dcid = session.peer_cid };
        break :blk try short_header.encode(&hdr_buf);
    };

    try out.appendSlice(allocator, hdr_buf[0..hdr_len]);

    var pn_buf: [8]u8 = undefined;
    const pn_len = try quic.encodeVarInt(session.next_packet_number, &pn_buf);
    session.next_packet_number += 1;
    try out.appendSlice(allocator, pn_buf[0..pn_len]);
}

fn decodeHTTP3StreamDatagram(datagram: []const u8, session: *HTTP3QUICSession) !DecodedHTTP3StreamDatagram {
    if (datagram.len == 0) return error.InvalidResponse;

    var offset: usize = 0;

    if ((datagram[0] & 0x80) != 0) {
        const long_decoded = try quic.LongHeader.decode(datagram);
        offset = long_decoded.len;
        if (long_decoded.header.scid.len > 0) {
            session.peer_cid = long_decoded.header.scid;
        }
    } else {
        const short_decoded = try quic.ShortHeader.decode(datagram, session.local_cid.len);
        offset = short_decoded.len;
    }

    const packet_number = try quic.decodeVarInt(datagram[offset..]);
    _ = packet_number.value;
    offset += packet_number.len;

    if (offset >= datagram.len) return error.InvalidResponse;
    if (!quic.FrameType.isStream(@as(u64, datagram[offset]))) return error.ProtocolError;

    const stream_decoded = try quic.StreamFrame.decode(datagram[offset..]);
    if (stream_decoded.len != datagram[offset..].len) return error.ProtocolError;

    return .{
        .stream_id = stream_decoded.frame.stream_id,
        .fin = stream_decoded.frame.fin,
        .data = stream_decoded.frame.data,
    };
}

fn toConnectionSettings(settings: types.HTTP2Settings, allow_push: bool) http.HTTP2Connection.HTTP2ConnectionSettings {
    return .{
        .header_table_size = settings.header_table_size,
        .enable_push = settings.enable_push and allow_push,
        .max_concurrent_streams = settings.max_concurrent_streams,
        .initial_window_size = settings.initial_window_size,
        .max_frame_size = settings.max_frame_size,
        .max_header_list_size = settings.max_header_list_size,
    };
}

fn buildAuthority(allocator: Allocator, req: *const Request, authority_buf: *?[]u8) ![]const u8 {
    const host = req.uri.host orelse return error.InvalidUri;
    const explicit_port = req.uri.port orelse return host;
    const default_port: u16 = if (req.uri.isTLS()) 443 else 80;

    if (explicit_port == default_port) return host;

    authority_buf.* = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, explicit_port });
    return authority_buf.*.?;
}

fn buildPseudoHeaders(
    allocator: Allocator,
    req: *Request,
    header_entries: anytype,
    owned_header_names: anytype,
    path_buf: *?[]u8,
    authority_buf: *?[]u8,
) !void {
    const path = if (req.uri.query) |q| blk: {
        path_buf.* = try std.fmt.allocPrint(allocator, "{s}?{s}", .{ req.uri.path, q });
        break :blk path_buf.*.?;
    } else req.uri.path;

    const authority = try buildAuthority(allocator, req, authority_buf);

    const method_value = if (req.method == .CUSTOM)
        (req.custom_method orelse "CUSTOM")
    else
        req.method.toString();

    try header_entries.append(allocator, .{ .name = ":method", .value = method_value });
    try header_entries.append(allocator, .{ .name = ":path", .value = path });
    try header_entries.append(allocator, .{ .name = ":scheme", .value = if (req.uri.isTLS()) "https" else "http" });
    try header_entries.append(allocator, .{ .name = ":authority", .value = authority });

    for (req.headers.entries.items) |entry| {
        if (common.isConnectionSpecificHeader(entry.name) or std.ascii.eqlIgnoreCase(entry.name, HeaderName.HOST)) {
            continue;
        }
        if (entry.name.len > 0 and entry.name[0] == ':') continue;

        const lowered_name = try common.dupLowerAscii(allocator, entry.name);
        try owned_header_names.append(allocator, lowered_name);
        try header_entries.append(allocator, .{ .name = lowered_name, .value = entry.value });
    }
}

fn writeHTTP2Frame(
    transport: anytype,
    frame_type: http.HTTP2FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) !void {
    const header = http.HTTP2FrameHeader{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    };
    const raw_header = header.serialize();
    try transport.writeAll(&raw_header);
    if (payload.len > 0) {
        try transport.writeAll(payload);
    }
}

fn applyResponseHeaderBlock(
    self: *Client,
    stream_manager: *h2stream.StreamManager,
    header_block: []const u8,
    flags: u8,
    expect_initial_headers: bool,
    status_code: *?u16,
    response_headers: *Headers,
) !void {
    const parsed = try h2stream.parseHeadersFramePayload(stream_manager, header_block, flags, self.allocator);
    defer {
        for (parsed.headers) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.allocator.free(parsed.headers);
    }

    var saw_status = false;

    for (parsed.headers) |header| {
        if (header.name.len > 0 and header.name[0] == ':') {
            if (mem.eql(u8, header.name, ":status")) {
                if (!expect_initial_headers or status_code.* != null or saw_status) {
                    return error.ProtocolError;
                }
                status_code.* = std.fmt.parseInt(u16, header.value, 10) catch return error.InvalidResponse;
                saw_status = true;
            } else {
                return error.ProtocolError;
            }
            continue;
        }

        if (common.isConnectionSpecificHeader(header.name)) continue;
        try response_headers.append(header.name, header.value);
    }

    if (expect_initial_headers and !saw_status and status_code.* == null) {
        return error.InvalidResponse;
    }
}

const PolicyTestServer = struct {
    listener: *TcpListener,
    responses: []const []const u8,
    requests: [8][8192]u8 = undefined,
    request_lengths: [8]usize = [_]usize{0} ** 8,
    request_count: usize = 0,
    failure: ?anyerror = null,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.failure = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        if (self.responses.len > self.requests.len) return error.TooManyTestResponses;

        for (self.responses, 0..) |response, index| {
            var accepted = try self.listener.accept();
            {
                defer accepted.socket.close();

                var length: usize = 0;
                while (length < self.requests[index].len) {
                    const n = try accepted.socket.recv(self.requests[index][length..]);
                    if (n == 0) return error.UnexpectedEndOfStream;
                    length += n;
                    if (mem.indexOf(u8, self.requests[index][0..length], "\r\n\r\n") != null) break;
                }
                self.request_lengths[index] = length;
                self.request_count += 1;
                try accepted.socket.sendAll(response);
            }
        }
    }

    fn request(self: *const @This(), index: usize) []const u8 {
        return self.requests[index][0..self.request_lengths[index]];
    }
};

const PolicyInterceptorCounts = struct {
    requests: u32 = 0,
    responses: u32 = 0,
    retries: u32 = 0,
    redirects: u32 = 0,
    last_retry_attempt: u32 = 0,
    logical_request_id: u64 = 0,
    context_mismatch: bool = false,

    fn observe(self: *@This(), attempt: *const AttemptContext) void {
        if (self.logical_request_id == 0) {
            self.logical_request_id = attempt.logical_request_id;
        } else if (self.logical_request_id != attempt.logical_request_id) {
            self.context_mismatch = true;
        }
    }

    fn onRequest(_: *Request, attempt: *const AttemptContext, context: ?*anyopaque) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.observe(attempt);
        self.requests += 1;
    }

    fn onResponse(_: *Response, attempt: *const AttemptContext, context: ?*anyopaque) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.observe(attempt);
        self.responses += 1;
    }

    fn onRetry(attempt: *const AttemptContext, context: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.observe(attempt);
        self.last_retry_attempt = attempt.attempt;
        self.retries += 1;
    }

    fn onRedirect(_: []const u8, attempt: *const AttemptContext, context: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.observe(attempt);
        self.redirects += 1;
    }
};

fn makePolicyTestResponse(
    allocator: Allocator,
    status: []const u8,
    headers: []const [2][]const u8,
    body: []const u8,
) ![]u8 {
    var bytes = std.ArrayList(u8).empty;
    errdefer bytes.deinit(allocator);
    const writer = list_writer.init(allocator, &bytes);

    try writer.print("HTTP/1.1 {s}\r\n", .{status});
    for (headers) |header| {
        try writer.print("{s}: {s}\r\n", .{ header[0], header[1] });
    }
    try writer.print("Content-Length: {d}\r\nConnection: close\r\n\r\n", .{body.len});
    try writer.writeAll(body);
    return bytes.toOwnedSlice(allocator);
}

fn policyTestUrl(allocator: Allocator, listener: *TcpListener, path: []const u8) ![]u8 {
    const address = try listener.getLocalAddress();
    return std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}{s}", .{ address.getPort(), path });
}

fn requestHeaderValue(request_bytes: []const u8, name: []const u8) ?[]const u8 {
    var lines = mem.splitSequence(u8, request_bytes, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) {
            return mem.trim(u8, line[colon + 1 ..], " \t");
        }
    }
    return null;
}

fn requestHeaderCount(request_bytes: []const u8, name: []const u8) usize {
    var count: usize = 0;
    var lines = mem.splitSequence(u8, request_bytes, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) count += 1;
    }
    return count;
}

test "Client initialization" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    try std.testing.expectEqualStrings(meta.default_user_agent, client.configuration().user_agent);
}

test "Client with config" {
    const allocator = std.testing.allocator;
    var client = Client.initWithConfig(allocator, .{
        .base_url = "http://httpbun.com",
        .user_agent = "TestClient/1.0",
    });
    defer client.deinit();

    try std.testing.expectEqualStrings("http://httpbun.com", client.configuration().base_url.?);
}

test "Client initForBaseUrl helper" {
    const allocator = std.testing.allocator;
    var client = Client.initForBaseUrl(allocator, "http://httpbun.com");
    defer client.deinit();

    try std.testing.expectEqualStrings("http://httpbun.com", client.configuration().base_url.?);
}

test "Client initialization defaults" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    try std.testing.expect(client.configuration().base_url == null);
    try std.testing.expect(client.configuration().keep_alive);
    try std.testing.expect(client.configuration().policy.redirect == .policy);
    try std.testing.expect(client.configuration().verify_ssl);
    try std.testing.expectEqual(@as(u32, 20), client.configuration().pool_max_connections);
    try std.testing.expectEqual(@as(u32, 5), client.configuration().pool_max_per_host);
}

test "ClientConfig builder helpers" {
    const default_headers = [_][2][]const u8{
        .{ "Accept", "application/json" },
    };

    const cfg = ClientConfig.defaults()
        .withBaseUrl("http://httpbun.com")
        .withTimeouts(types.Timeouts.fast())
        .withRetryPolicy(types.RetryPolicy.noRetry())
        .withRedirectPolicy(types.RedirectPolicy.strict())
        .withDefaultHeaders(&default_headers)
        .withUserAgent("MyClient/1.0")
        .withFollowRedirects(false)
        .withProtocols(true, false)
        .withHTTP2Settings(.{ .max_concurrent_streams = 42 })
        .withHTTP3Settings(.{ .enable_datagrams = true })
        .withSslVerification(false)
        .withKeepAlive(false)
        .withMaxResponseSize(1024)
        .withPoolLimits(64, 16)
        .withProxy(.{ .host = "127.0.0.1", .port = 8080 });

    try std.testing.expectEqualStrings("http://httpbun.com", cfg.base_url.?);
    try std.testing.expectEqual(@as(u64, 5_000), cfg.timeouts.connect_ms);
    switch (cfg.policy.retry) {
        .policy => |policy| try std.testing.expectEqual(@as(u32, 0), policy.max_retries),
        .disabled => return error.TestUnexpectedResult,
    }
    try std.testing.expect(cfg.default_headers != null);
    try std.testing.expectEqual(@as(usize, 1), cfg.default_headers.?.len);
    try std.testing.expectEqualStrings("MyClient/1.0", cfg.user_agent);
    try std.testing.expect(cfg.policy.redirect == .disabled);
    try std.testing.expect(cfg.http2_enabled);
    try std.testing.expect(!cfg.http3_enabled);
    try std.testing.expectEqual(@as(u32, 42), cfg.http2_settings.max_concurrent_streams);
    try std.testing.expect(cfg.http3_settings.enable_datagrams);
    try std.testing.expect(!cfg.verify_ssl);
    try std.testing.expect(!cfg.keep_alive);
    try std.testing.expectEqual(@as(usize, 1024), cfg.max_response_size);
    try std.testing.expectEqual(@as(u32, 64), cfg.pool_max_connections);
    try std.testing.expectEqual(@as(u32, 16), cfg.pool_max_per_host);
    try std.testing.expect(cfg.proxy != null);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.proxy.?.host);
    try std.testing.expectEqual(@as(u16, 8080), cfg.proxy.?.port);

    const strict_redirects = ClientConfig.defaults().withRedirectPolicy(types.RedirectPolicy.strict());
    switch (strict_redirects.policy.redirect) {
        .policy => |policy| try std.testing.expect(policy.preserve_method),
        .disabled => return error.TestUnexpectedResult,
    }

    const embedding_owned = ClientConfig.defaults().withPolicy(types.ClientPolicy.embeddingOwned());
    try std.testing.expect(embedding_owned.policy.retry == .disabled);
    try std.testing.expect(embedding_owned.policy.redirect == .disabled);
}

test "RequestOptions builder helpers" {
    const headers = [_][2][]const u8{
        .{ "Authorization", "Bearer test" },
        .{ "Accept", "application/json" },
    };
    const query_params = [_][2][]const u8{
        .{ "page", "1" },
        .{ "sort", "desc" },
    };
    const form_fields = [_][2][]const u8{
        .{ "email", "user@example.com" },
    };
    var cancel_token = types.CancellationToken.init();

    const opts = RequestOptions.defaults()
        .withHeaders(&headers)
        .withQueryParams(&query_params)
        .withJson("{\"ok\":true}")
        .withFormUrlEncoded(&form_fields)
        .withBearerToken("token-123")
        .withTimeoutMs(2_500)
        .withCancellation(&cancel_token)
        .withFollowRedirects(false)
        .withVersion(.HTTP_2);

    try std.testing.expect(opts.headers != null);
    try std.testing.expectEqual(@as(usize, 2), opts.headers.?.len);
    try std.testing.expect(opts.query_params != null);
    try std.testing.expectEqual(@as(usize, 2), opts.query_params.?.len);
    try std.testing.expectEqualStrings("{\"ok\":true}", opts.json.?);
    try std.testing.expect(opts.form_fields != null);
    try std.testing.expectEqual(@as(usize, 1), opts.form_fields.?.len);
    try std.testing.expectEqualStrings("token-123", opts.bearer_token.?);
    try std.testing.expect(opts.basic_auth == null);
    try std.testing.expectEqual(@as(u64, 2_500), opts.timeout_ms.?);
    try std.testing.expect(opts.cancel_token.? == &cancel_token);
    try std.testing.expect(opts.policy.redirect.? == .disabled);
    try std.testing.expectEqual(types.Version.HTTP_2, opts.version.?);

    const basic = RequestOptions.defaults().withBasicAuth("demo", "pass");
    try std.testing.expect(basic.basic_auth != null);
    try std.testing.expectEqualStrings("demo", basic.basic_auth.?.username);
    try std.testing.expectEqualStrings("pass", basic.basic_auth.?.password);
    try std.testing.expect(basic.bearer_token == null);

    const h3 = RequestOptions.defaults().withHTTP3();
    try std.testing.expectEqual(types.Version.HTTP_3, h3.version.?);

    const embedding_owned = RequestOptions.defaults().withPolicy(types.RequestPolicyOverrides.embeddingOwned());
    try std.testing.expect(embedding_owned.policy.retry.? == .disabled);
    try std.testing.expect(embedding_owned.policy.redirect.? == .disabled);
}

test "embedding-owned request disables redirect cookies encoding and decompression" {
    const allocator = std.testing.allocator;
    const plaintext = "encoded redirect body";
    const encoded = try compression_util.compress(allocator, .gzip, plaintext);
    defer allocator.free(encoded);

    const response_headers = [_][2][]const u8{
        .{ "Location", "/next" },
        .{ "Set-Cookie", "server_cookie=new; Path=/" },
        .{ "Content-Encoding", "gzip" },
    };
    const response_bytes = try makePolicyTestResponse(allocator, "302 Found", &response_headers, encoded);
    defer allocator.free(response_bytes);

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const responses = [_][]const u8{response_bytes};
    var server = PolicyTestServer{ .listener = &listener, .responses = &responses };
    const thread = try std.Thread.spawn(.{}, PolicyTestServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        thread.join();
    };

    const url = try policyTestUrl(allocator, &listener, "/redirect");
    defer allocator.free(url);

    var client = Client.initWithConfig(allocator, .{
        .keep_alive = false,
        .timeouts = types.Timeouts.fast(),
    });
    defer client.deinit();
    try client.setCookie("session", "jar-value");

    var counts = PolicyInterceptorCounts{};
    try client.addInterceptor(.{
        .request_fn = PolicyInterceptorCounts.onRequest,
        .response_fn = PolicyInterceptorCounts.onResponse,
        .retry_fn = PolicyInterceptorCounts.onRetry,
        .redirect_fn = PolicyInterceptorCounts.onRedirect,
        .context = &counts,
    });

    var response = try client.get(url, .{
        .policy = types.RequestPolicyOverrides.embeddingOwned(),
    });
    defer response.deinit();

    thread.join();
    joined = true;

    try std.testing.expect(server.failure == null);
    try std.testing.expectEqual(@as(usize, 1), server.request_count);
    try std.testing.expectEqual(@as(u16, 302), response.status.code);
    try std.testing.expectEqualSlices(u8, encoded, response.body.?);
    try std.testing.expectEqualStrings("gzip", response.headers.get(HeaderName.CONTENT_ENCODING).?);
    try std.testing.expect(requestHeaderValue(server.request(0), HeaderName.COOKIE) == null);
    try std.testing.expect(requestHeaderValue(server.request(0), HeaderName.ACCEPT_ENCODING) == null);
    try std.testing.expect(requestHeaderValue(server.request(0), HeaderName.USER_AGENT) == null);
    try std.testing.expectEqual(@as(usize, 1), client.cookieCount());
    try std.testing.expectEqual(@as(u32, 1), counts.requests);
    try std.testing.expectEqual(@as(u32, 1), counts.responses);
    try std.testing.expectEqual(@as(u32, 0), counts.retries);
    try std.testing.expectEqual(@as(u32, 0), counts.redirects);
}

test "embedding-owned request returns first retryable response" {
    const allocator = std.testing.allocator;
    const response_bytes = try makePolicyTestResponse(allocator, "503 Service Unavailable", &.{}, "unavailable");
    defer allocator.free(response_bytes);

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const responses = [_][]const u8{response_bytes};
    var server = PolicyTestServer{ .listener = &listener, .responses = &responses };
    const thread = try std.Thread.spawn(.{}, PolicyTestServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        thread.join();
    };

    const url = try policyTestUrl(allocator, &listener, "/retry");
    defer allocator.free(url);

    var client = Client.initWithConfig(allocator, .{
        .keep_alive = false,
        .timeouts = types.Timeouts.fast(),
    });
    defer client.deinit();

    var counts = PolicyInterceptorCounts{};
    try client.addInterceptor(.{
        .request_fn = PolicyInterceptorCounts.onRequest,
        .response_fn = PolicyInterceptorCounts.onResponse,
        .retry_fn = PolicyInterceptorCounts.onRetry,
        .context = &counts,
    });

    var response = try client.get(url, .{
        .policy = types.RequestPolicyOverrides.embeddingOwned(),
    });
    defer response.deinit();

    thread.join();
    joined = true;

    try std.testing.expect(server.failure == null);
    try std.testing.expectEqual(@as(usize, 1), server.request_count);
    try std.testing.expectEqual(@as(u16, 503), response.status.code);
    try std.testing.expectEqual(@as(u32, 0), counts.retries);
}

test "request retry override enables only retry behavior" {
    const allocator = std.testing.allocator;
    const unavailable = try makePolicyTestResponse(allocator, "503 Service Unavailable", &.{}, "retry");
    defer allocator.free(unavailable);
    const success = try makePolicyTestResponse(allocator, "200 OK", &.{}, "ok");
    defer allocator.free(success);

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const responses = [_][]const u8{ unavailable, success };
    var server = PolicyTestServer{ .listener = &listener, .responses = &responses };
    const thread = try std.Thread.spawn(.{}, PolicyTestServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        thread.join();
    };

    const url = try policyTestUrl(allocator, &listener, "/retry");
    defer allocator.free(url);

    var client = Client.initWithConfig(allocator, .{
        .policy = types.ClientPolicy.embeddingOwned(),
        .keep_alive = false,
        .timeouts = types.Timeouts.fast(),
    });
    defer client.deinit();

    var counts = PolicyInterceptorCounts{};
    try client.addInterceptor(.{
        .request_fn = PolicyInterceptorCounts.onRequest,
        .response_fn = PolicyInterceptorCounts.onResponse,
        .retry_fn = PolicyInterceptorCounts.onRetry,
        .context = &counts,
    });

    var response = try client.get(url, .{
        .policy = .{
            .retry = .{ .policy = .{
                .max_retries = 1,
                .initial_delay_ms = 0,
                .max_delay_ms = 0,
                .jitter = 0,
            } },
        },
    });
    defer response.deinit();

    thread.join();
    joined = true;

    try std.testing.expect(server.failure == null);
    try std.testing.expectEqual(@as(usize, 2), server.request_count);
    try std.testing.expectEqual(@as(u16, 200), response.status.code);
    try std.testing.expectEqual(@as(u32, 2), counts.requests);
    try std.testing.expectEqual(@as(u32, 2), counts.responses);
    try std.testing.expectEqual(@as(u32, 1), counts.retries);
    try std.testing.expectEqual(@as(u32, 1), counts.last_retry_attempt);
    try std.testing.expect(!counts.context_mismatch);
    try std.testing.expect(requestHeaderValue(server.request(0), HeaderName.ACCEPT_ENCODING) == null);
}

test "retry notification does not fire when cancellation prevents next attempt" {
    const allocator = std.testing.allocator;
    const unavailable = try makePolicyTestResponse(allocator, "503 Service Unavailable", &.{}, "stop");
    defer allocator.free(unavailable);

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const responses = [_][]const u8{unavailable};
    var server = PolicyTestServer{ .listener = &listener, .responses = &responses };
    const thread = try std.Thread.spawn(.{}, PolicyTestServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        thread.join();
    };

    const url = try policyTestUrl(allocator, &listener, "/cancel-retry");
    defer allocator.free(url);
    var client = Client.initWithConfig(allocator, .{
        .keep_alive = false,
        .policy = types.ClientPolicy.embeddingOwned(),
        .timeouts = types.Timeouts.fast(),
    });
    defer client.deinit();

    const CallbackState = struct {
        token: *types.CancellationToken,
        retries: u32 = 0,

        fn onResponse(_: *Response, _: *const AttemptContext, context: ?*anyopaque) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.token.cancel();
        }

        fn onRetry(_: *const AttemptContext, context: ?*anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.retries += 1;
        }
    };

    var token = types.CancellationToken.init();
    var callback_state = CallbackState{ .token = &token };
    try client.addInterceptor(.{
        .response_fn = CallbackState.onResponse,
        .retry_fn = CallbackState.onRetry,
        .context = &callback_state,
    });

    try std.testing.expectError(error.Cancelled, client.get(url, .{
        .cancel_token = &token,
        .policy = .{ .retry = .{ .policy = .{
            .max_retries = 1,
            .initial_delay_ms = 100,
            .max_delay_ms = 100,
            .jitter = 0,
        } } },
    }));

    thread.join();
    joined = true;
    try std.testing.expect(server.failure == null);
    try std.testing.expectEqual(@as(usize, 1), server.request_count);
    try std.testing.expectEqual(@as(u32, 0), callback_state.retries);
}

test "request redirect override enables only redirect behavior" {
    const allocator = std.testing.allocator;
    const redirect_headers = [_][2][]const u8{.{ "Location", "/final" }};
    const redirect = try makePolicyTestResponse(allocator, "302 Found", &redirect_headers, "");
    defer allocator.free(redirect);
    const success = try makePolicyTestResponse(allocator, "200 OK", &.{}, "final");
    defer allocator.free(success);

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const responses = [_][]const u8{ redirect, success };
    var server = PolicyTestServer{ .listener = &listener, .responses = &responses };
    const thread = try std.Thread.spawn(.{}, PolicyTestServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        thread.join();
    };

    const url = try policyTestUrl(allocator, &listener, "/redirect");
    defer allocator.free(url);

    var client = Client.initWithConfig(allocator, .{
        .policy = types.ClientPolicy.embeddingOwned(),
        .keep_alive = false,
        .timeouts = types.Timeouts.fast(),
    });
    defer client.deinit();

    var counts = PolicyInterceptorCounts{};
    try client.addInterceptor(.{
        .redirect_fn = PolicyInterceptorCounts.onRedirect,
        .context = &counts,
    });

    var response = try client.get(url, .{
        .policy = .{ .redirect = .{ .policy = .{ .max_redirects = 1 } } },
    });
    defer response.deinit();

    thread.join();
    joined = true;

    try std.testing.expect(server.failure == null);
    try std.testing.expectEqual(@as(usize, 2), server.request_count);
    try std.testing.expectEqual(@as(u16, 200), response.status.code);
    try std.testing.expectEqual(@as(u32, 1), counts.redirects);
    try std.testing.expect(requestHeaderValue(server.request(0), HeaderName.ACCEPT_ENCODING) == null);
}

test "cookie policy overrides send and store independently and preserve caller header" {
    const allocator = std.testing.allocator;
    const ignored_headers = [_][2][]const u8{.{ "Set-Cookie", "ignored=value; Path=/" }};
    const ignored = try makePolicyTestResponse(allocator, "200 OK", &ignored_headers, "send");
    defer allocator.free(ignored);
    const stored_headers = [_][2][]const u8{.{ "Set-Cookie", "stored=value; Path=/" }};
    const stored = try makePolicyTestResponse(allocator, "200 OK", &stored_headers, "store");
    defer allocator.free(stored);
    const caller = try makePolicyTestResponse(allocator, "200 OK", &.{}, "caller");
    defer allocator.free(caller);

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const responses = [_][]const u8{ ignored, stored, caller };
    var server = PolicyTestServer{ .listener = &listener, .responses = &responses };
    const thread = try std.Thread.spawn(.{}, PolicyTestServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        thread.join();
    };

    const url = try policyTestUrl(allocator, &listener, "/cookies");
    defer allocator.free(url);

    var client = Client.initWithConfig(allocator, .{
        .policy = types.ClientPolicy.embeddingOwned(),
        .keep_alive = false,
        .timeouts = types.Timeouts.fast(),
    });
    defer client.deinit();
    try client.setCookie("session", "jar-value");

    var send_response = try client.get(url, .{
        .policy = .{ .cookies = .send_only },
    });
    send_response.deinit();
    try std.testing.expectEqual(@as(usize, 1), client.cookieCount());

    var store_response = try client.get(url, .{
        .policy = .{ .cookies = .store_only },
    });
    store_response.deinit();
    try std.testing.expectEqual(@as(usize, 2), client.cookieCount());

    const caller_headers = [_][2][]const u8{.{ HeaderName.COOKIE, "caller=value" }};
    var caller_response = try client.get(url, .{
        .headers = &caller_headers,
        .policy = .{ .cookies = .send_and_store },
    });
    caller_response.deinit();

    thread.join();
    joined = true;

    try std.testing.expect(server.failure == null);
    try std.testing.expectEqual(@as(usize, 3), server.request_count);
    try std.testing.expect(mem.indexOf(u8, requestHeaderValue(server.request(0), HeaderName.COOKIE).?, "session=jar-value") != null);
    try std.testing.expect(requestHeaderValue(server.request(1), HeaderName.COOKIE) == null);
    try std.testing.expectEqualStrings("caller=value", requestHeaderValue(server.request(2), HeaderName.COOKIE).?);
}

test "encoding and decompression overrides are independent and preserve caller header" {
    const allocator = std.testing.allocator;
    const plaintext = "decompressed response";
    const encoded = try compression_util.compress(allocator, .gzip, plaintext);
    defer allocator.free(encoded);

    const first = try makePolicyTestResponse(allocator, "200 OK", &.{}, "first");
    defer allocator.free(first);
    const encoded_headers = [_][2][]const u8{
        .{ "X-A", "1" },
        .{ "X-B", "x" },
        .{ "X-A", "2" },
        .{ "Content-Encoding", "gzip" },
    };
    const second = try makePolicyTestResponse(allocator, "200 OK", &encoded_headers, encoded);
    defer allocator.free(second);

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const responses = [_][]const u8{ first, second };
    var server = PolicyTestServer{ .listener = &listener, .responses = &responses };
    const thread = try std.Thread.spawn(.{}, PolicyTestServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        thread.join();
    };

    const url = try policyTestUrl(allocator, &listener, "/encoding");
    defer allocator.free(url);

    var client = Client.initWithConfig(allocator, .{
        .policy = types.ClientPolicy.embeddingOwned(),
        .keep_alive = false,
        .timeouts = types.Timeouts.fast(),
    });
    defer client.deinit();

    var first_response = try client.get(url, .{
        .policy = .{ .accept_encoding = .{ .explicit = "gzip" } },
    });
    defer first_response.deinit();
    try std.testing.expectEqualStrings("first", first_response.body.?);

    const caller_headers = [_][2][]const u8{.{ HeaderName.ACCEPT_ENCODING, "caller-coding" }};
    var second_response = try client.get(url, .{
        .headers = &caller_headers,
        .policy = .{
            .accept_encoding = .{ .explicit = "br" },
            .decompression = .enabled,
        },
    });
    defer second_response.deinit();

    thread.join();
    joined = true;

    try std.testing.expect(server.failure == null);
    try std.testing.expectEqualStrings("gzip", requestHeaderValue(server.request(0), HeaderName.ACCEPT_ENCODING).?);
    try std.testing.expectEqualStrings("caller-coding", requestHeaderValue(server.request(1), HeaderName.ACCEPT_ENCODING).?);
    try std.testing.expectEqualStrings(plaintext, second_response.body.?);
    try std.testing.expectEqualStrings("gzip", second_response.headers.get(HeaderName.CONTENT_ENCODING).?);
    const response_entries = second_response.headers.iterator();
    try std.testing.expectEqualStrings("X-A", response_entries[0].name);
    try std.testing.expectEqualStrings("X-B", response_entries[1].name);
    try std.testing.expectEqualStrings("X-A", response_entries[2].name);
}

test "request headers preserve ordered duplicates without automatic coalescing" {
    const allocator = std.testing.allocator;
    const response_bytes = try makePolicyTestResponse(allocator, "200 OK", &.{}, "ok");
    defer allocator.free(response_bytes);

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const responses = [_][]const u8{response_bytes};
    var server = PolicyTestServer{ .listener = &listener, .responses = &responses };
    const thread = try std.Thread.spawn(.{}, PolicyTestServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        thread.join();
    };

    const url = try policyTestUrl(allocator, &listener, "/duplicates");
    defer allocator.free(url);
    var client = Client.initWithConfig(allocator, .{
        .keep_alive = false,
        .timeouts = types.Timeouts.fast(),
    });
    defer client.deinit();

    const request_headers = [_][2][]const u8{
        .{ "Host", "first.example" },
        .{ "Host", "override.example" },
        .{ "x-ms-meta-value", "one" },
        .{ "Cookie", "a=1" },
        .{ "x-ms-other", "middle" },
        .{ "x-ms-meta-value", "two" },
        .{ "Cookie", "b=2" },
    };
    var response = try client.get(url, .{
        .headers = &request_headers,
        .policy = types.RequestPolicyOverrides.embeddingOwned(),
    });
    defer response.deinit();

    thread.join();
    joined = true;
    try std.testing.expect(server.failure == null);
    const wire = server.request(0);
    try std.testing.expectEqual(@as(usize, 1), requestHeaderCount(wire, HeaderName.HOST));
    try std.testing.expectEqualStrings("override.example", requestHeaderValue(wire, HeaderName.HOST).?);
    const first_xms = mem.indexOf(u8, wire, "x-ms-meta-value: one\r\n").?;
    const first_cookie = mem.indexOf(u8, wire, "Cookie: a=1\r\n").?;
    const middle_xms = mem.indexOf(u8, wire, "x-ms-other: middle\r\n").?;
    const second_xms = mem.indexOf(u8, wire, "x-ms-meta-value: two\r\n").?;
    const second_cookie = mem.indexOf(u8, wire, "Cookie: b=2\r\n").?;
    try std.testing.expect(first_xms < first_cookie);
    try std.testing.expect(first_cookie < middle_xms);
    try std.testing.expect(middle_xms < second_xms);
    try std.testing.expect(second_xms < second_cookie);
}

test "request framing headers are normalized and conflicting transfer encoding is rejected" {
    const allocator = std.testing.allocator;
    const response_bytes = try makePolicyTestResponse(allocator, "200 OK", &.{}, "ok");
    defer allocator.free(response_bytes);

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const responses = [_][]const u8{response_bytes};
    var server = PolicyTestServer{ .listener = &listener, .responses = &responses };
    const thread = try std.Thread.spawn(.{}, PolicyTestServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        thread.join();
    };

    const url = try policyTestUrl(allocator, &listener, "/framing");
    defer allocator.free(url);
    var client = Client.initWithConfig(allocator, .{
        .keep_alive = false,
        .policy = types.ClientPolicy.embeddingOwned(),
        .timeouts = types.Timeouts.fast(),
    });
    defer client.deinit();

    const content_lengths = [_][2][]const u8{
        .{ "Content-Length", "99" },
        .{ "Content-Length", "100" },
    };
    var response = try client.post(url, .{ .headers = &content_lengths, .body = "abc" });
    defer response.deinit();
    thread.join();
    joined = true;

    try std.testing.expect(server.failure == null);
    try std.testing.expectEqual(@as(usize, 1), requestHeaderCount(server.request(0), HeaderName.CONTENT_LENGTH));
    try std.testing.expectEqualStrings("3", requestHeaderValue(server.request(0), HeaderName.CONTENT_LENGTH).?);

    const transfer_encoding = [_][2][]const u8{.{ "Transfer-Encoding", "chunked" }};
    try std.testing.expectError(
        error.ConflictingFramingHeaders,
        client.post("http://127.0.0.1:1/rejected", .{
            .headers = &transfer_encoding,
            .body = "abc",
        }),
    );
}

test "HTTP2 response header decoding preserves duplicates and order" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();
    var manager = h2stream.StreamManager.init(allocator, true);
    defer manager.deinit();

    const encoded = try h2stream.buildHeadersFramePayload(&manager, &.{
        .{ .name = ":status", .value = "200", .representation = .without_indexing },
        .{ .name = "x-a", .value = "1", .representation = .without_indexing },
        .{ .name = "x-b", .value = "x", .representation = .without_indexing },
        .{ .name = "x-a", .value = "2", .representation = .without_indexing },
        .{ .name = "set-cookie", .value = "a=1", .representation = .without_indexing },
        .{ .name = "set-cookie", .value = "b=2", .representation = .without_indexing },
    }, null, allocator);
    defer allocator.free(encoded.payload);

    var status_code: ?u16 = null;
    var headers = Headers.init(allocator);
    defer headers.deinit();
    try applyResponseHeaderBlock(
        &client,
        &manager,
        encoded.payload,
        encoded.flags,
        true,
        &status_code,
        &headers,
    );

    try std.testing.expectEqual(@as(?u16, 200), status_code);
    const entries = headers.iterator();
    try std.testing.expectEqualStrings("x-a", entries[0].name);
    try std.testing.expectEqualStrings("x-b", entries[1].name);
    try std.testing.expectEqualStrings("x-a", entries[2].name);
    const x_a = try headers.getAll("x-a", allocator);
    defer allocator.free(x_a);
    try std.testing.expectEqual(@as(usize, 2), x_a.len);
    try std.testing.expectEqualStrings("1", x_a[0]);
    try std.testing.expectEqualStrings("2", x_a[1]);
    const cookies = try headers.getAll("set-cookie", allocator);
    defer allocator.free(cookies);
    try std.testing.expectEqual(@as(usize, 2), cookies.len);
}

test "managed policy keeps automatic cookies encoding storage and decompression" {
    const allocator = std.testing.allocator;
    const plaintext = "managed response";
    const encoded = try compression_util.compress(allocator, .gzip, plaintext);
    defer allocator.free(encoded);

    const response_headers = [_][2][]const u8{
        .{ "Set-Cookie", "managed=value; Path=/" },
        .{ "Content-Encoding", "gzip" },
    };
    const response_bytes = try makePolicyTestResponse(allocator, "200 OK", &response_headers, encoded);
    defer allocator.free(response_bytes);

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const responses = [_][]const u8{response_bytes};
    var server = PolicyTestServer{ .listener = &listener, .responses = &responses };
    const thread = try std.Thread.spawn(.{}, PolicyTestServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        thread.join();
    };

    const url = try policyTestUrl(allocator, &listener, "/managed");
    defer allocator.free(url);

    var client = Client.initWithConfig(allocator, .{
        .keep_alive = false,
        .timeouts = types.Timeouts.fast(),
    });
    defer client.deinit();
    try client.setCookie("session", "jar-value");

    var response = try client.get(url, .{});
    defer response.deinit();

    thread.join();
    joined = true;

    try std.testing.expect(server.failure == null);
    try std.testing.expectEqualStrings(plaintext, response.body.?);
    try std.testing.expectEqualStrings("gzip", response.headers.get(HeaderName.CONTENT_ENCODING).?);
    try std.testing.expect(mem.indexOf(u8, requestHeaderValue(server.request(0), HeaderName.COOKIE).?, "session=jar-value") != null);
    try std.testing.expectEqualStrings(types.AcceptEncodingPolicy.library_default_value, requestHeaderValue(server.request(0), HeaderName.ACCEPT_ENCODING).?);
    try std.testing.expectEqual(@as(usize, 2), client.cookieCount());
}

test "Client supports concurrent requests cookie updates and interceptor callbacks" {
    const allocator = std.testing.allocator;
    const request_count = 8;
    const response_bytes = try makePolicyTestResponse(allocator, "200 OK", &.{}, "ok");
    defer allocator.free(response_bytes);

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const responses = [_][]const u8{response_bytes} ** request_count;
    var server = PolicyTestServer{ .listener = &listener, .responses = &responses };
    const server_thread = try std.Thread.spawn(.{}, PolicyTestServer.run, .{&server});
    var server_joined = false;
    defer if (!server_joined) {
        listener.deinit();
        server_thread.join();
    };

    const url = try policyTestUrl(allocator, &listener, "/concurrent");
    defer allocator.free(url);

    var client = Client.initWithConfig(allocator, .{
        .pool_max_connections = request_count,
        .pool_max_per_host = request_count,
        .timeouts = types.Timeouts.fast(),
    });
    defer client.deinit();

    const Counts = struct {
        requests: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        responses: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        invalid_attempt: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        fn onRequest(_: *Request, attempt: *const AttemptContext, context: ?*anyopaque) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (attempt.attempt != 1 or attempt.redirect_count != 0) {
                self.invalid_attempt.store(true, .release);
            }
            _ = self.requests.fetchAdd(1, .acq_rel);
        }

        fn onResponse(_: *Response, attempt: *const AttemptContext, context: ?*anyopaque) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (attempt.attempt != 1 or attempt.redirect_count != 0) {
                self.invalid_attempt.store(true, .release);
            }
            _ = self.responses.fetchAdd(1, .acq_rel);
        }
    };

    var counts = Counts{};
    try client.addInterceptor(.{
        .request_fn = Counts.onRequest,
        .response_fn = Counts.onResponse,
        .context = &counts,
    });

    const Worker = struct {
        client: *Client,
        url: []const u8,
        index: usize,
        failure: *?anyerror,

        fn run(self: @This()) void {
            var name_buf: [32]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "cookie-{d}", .{self.index}) catch {
                self.failure.* = error.NoSpaceLeft;
                return;
            };
            self.client.setCookie(name, "value") catch |err| {
                self.failure.* = err;
                return;
            };
            var response = self.client.get(self.url, .{
                .policy = types.RequestPolicyOverrides.embeddingOwned(),
            }) catch |err| {
                self.failure.* = err;
                return;
            };
            defer response.deinit();
            if (response.status.code != 200) self.failure.* = error.TestUnexpectedResult;
        }
    };

    var failures = [_]?anyerror{null} ** request_count;
    var threads: [request_count]std.Thread = undefined;
    for (&threads, 0..) |*thread, index| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{Worker{
            .client = &client,
            .url = url,
            .index = index,
            .failure = &failures[index],
        }});
    }
    for (threads) |thread| thread.join();

    server_thread.join();
    server_joined = true;

    try std.testing.expect(server.failure == null);
    for (failures) |failure| try std.testing.expect(failure == null);
    try std.testing.expectEqual(@as(usize, request_count), client.cookieCount());
    try std.testing.expectEqual(@as(u32, request_count), counts.requests.load(.acquire));
    try std.testing.expectEqual(@as(u32, request_count), counts.responses.load(.acquire));
    try std.testing.expect(!counts.invalid_attempt.load(.acquire));
}

test "public Client preserves HTTP1 ALPN fallback and TLS reuse" {
    const allocator = std.testing.allocator;
    var tls_config = try tls_mod.loadServerTLSConfig(
        allocator,
        "examples/certs/server_ec.crt",
        "examples/certs/server_ec.key",
    );
    defer tls_config.deinit();

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const address = try listener.getLocalAddress();

    const LoopbackServer = struct {
        listener: *TcpListener,
        tls_config: *tls_mod.ServerTLSConfig,
        accepts: u32 = 0,
        handshakes: u32 = 0,
        requests: u32 = 0,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.failure = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.listener.accept();
            defer accepted.socket.close();
            self.accepts += 1;
            try accepted.socket.setRecvTimeout(30_000);
            try accepted.socket.setSendTimeout(30_000);

            var connection = try tls_mod.acceptServer(
                std.heap.page_allocator,
                &accepted.socket,
                &.{"http/1.1"},
                self.tls_config.*,
            );
            self.handshakes += 1;
            defer connection.closeNotify();
            try std.testing.expectEqualStrings("http/1.1", connection.negotiatedAlpn().?);

            var request_buf: [8192]u8 = undefined;
            while (self.requests < 2) {
                var length: usize = 0;
                while (mem.indexOf(u8, request_buf[0..length], "\r\n\r\n") == null) {
                    const n = try connection.read(request_buf[length..]);
                    if (n == 0) return error.UnexpectedEndOfStream;
                    length += n;
                }
                self.requests += 1;
                try connection.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfallback");
            }
        }
    };

    var server = LoopbackServer{ .listener = &listener, .tls_config = &tls_config };
    const server_thread = try std.Thread.spawn(.{}, LoopbackServer.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        server_thread.join();
    };

    var client = Client.initWithConfig(allocator, .{
        .verify_ssl = false,
        .http2_enabled = true,
        .keep_alive = true,
        .policy = types.ClientPolicy.embeddingOwned(),
        .timeouts = types.Timeouts.uniform(30_000),
    });
    defer client.deinit();
    const url = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/fallback", .{address.getPort()});
    defer allocator.free(url);

    var first = try client.get(url, .{});
    defer first.deinit();
    try std.testing.expectEqual(types.Version.HTTP_1_1, first.version);
    try std.testing.expectEqualStrings("fallback", first.body.?);
    try std.testing.expectEqual(@as(usize, 1), client.poolStats().idle);

    var second = try client.get(url, .{});
    defer second.deinit();
    try std.testing.expectEqual(types.Version.HTTP_1_1, second.version);
    try std.testing.expectEqualStrings("fallback", second.body.?);

    server_thread.join();
    joined = true;
    try std.testing.expect(server.failure == null);
    try std.testing.expectEqual(@as(u32, 1), server.accepts);
    try std.testing.expectEqual(@as(u32, 1), server.handshakes);
    try std.testing.expectEqual(@as(u32, 2), server.requests);
    try std.testing.expectEqual(@as(usize, 1), client.poolStats().total);
}

test "HTTP2 WINDOW_UPDATE persists connection credit and rejects invalid increments" {
    var manager = h2stream.StreamManager.init(std.testing.allocator, true);
    defer manager.deinit();
    const stream = try manager.createStream();
    const connection_header = http.HTTP2FrameHeader{
        .length = 4,
        .frame_type = .window_update,
        .flags = 0,
        .stream_id = 0,
    };
    const stream_header = http.HTTP2FrameHeader{
        .length = 4,
        .frame_type = .window_update,
        .flags = 0,
        .stream_id = stream.id,
    };

    manager.connection_send_window = 10;
    stream.send_window = 20;
    const five = h2stream.buildWindowUpdatePayload(5);
    try Client.applyHTTP2WindowUpdate(&manager, stream, connection_header, &five);
    try Client.applyHTTP2WindowUpdate(&manager, stream, stream_header, &five);
    try std.testing.expectEqual(@as(i32, 15), manager.connection_send_window);
    try std.testing.expectEqual(@as(i32, 25), stream.send_window);

    const zero = [_]u8{0} ** 4;
    try std.testing.expectError(
        error.ProtocolError,
        Client.applyHTTP2WindowUpdate(&manager, stream, connection_header, &zero),
    );

    manager.connection_send_window = std.math.maxInt(i32);
    const one = h2stream.buildWindowUpdatePayload(1);
    try std.testing.expectError(
        error.FlowControlError,
        Client.applyHTTP2WindowUpdate(&manager, stream, connection_header, &one),
    );
}

test "HTTP2 partial SETTINGS update retained peer settings" {
    var manager = h2stream.StreamManager.init(std.testing.allocator, true);
    defer manager.deinit();
    var initial = manager.peer_settings;
    initial.initial_window_size = 70_000;
    initial.max_concurrent_streams = 7;
    try manager.applyPeerSettings(initial);

    const Capture = struct {
        bytes: std.ArrayList(u8) = .empty,
        fn writeAll(self: *@This(), data: []const u8) !void {
            try self.bytes.appendSlice(std.testing.allocator, data);
        }
    };
    var capture = Capture{};
    defer capture.bytes.deinit(std.testing.allocator);

    var payload: [6]u8 = undefined;
    mem.writeInt(u16, payload[0..2], @intFromEnum(http.HTTP2Settings.max_frame_size), .big);
    mem.writeInt(u32, payload[2..6], 32_768, .big);
    const header = http.HTTP2FrameHeader{
        .length = payload.len,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    };
    var peer_max_frame_size: u32 = manager.peer_settings.max_frame_size;
    try Client.applyHTTP2SettingsUpdate(
        &capture,
        &manager,
        header,
        &payload,
        &peer_max_frame_size,
    );

    try std.testing.expectEqual(@as(u32, 70_000), manager.peer_settings.initial_window_size);
    try std.testing.expectEqual(@as(u32, 7), manager.peer_settings.max_concurrent_streams);
    try std.testing.expectEqual(@as(u32, 32_768), manager.peer_settings.max_frame_size);
    try std.testing.expectEqual(@as(u32, 32_768), peer_max_frame_size);
    try std.testing.expectEqual(@as(usize, 9), capture.bytes.items.len);
}

test "public Client reuses H2 with retained flow control settings and GOAWAY drain" {
    const allocator = std.testing.allocator;
    var tls_config = try tls_mod.loadServerTLSConfig(
        allocator,
        "examples/certs/server_ec.crt",
        "examples/certs/server_ec.key",
    );
    defer tls_config.deinit();

    var listener = try TcpListener.init(try address_mod.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const address = try listener.getLocalAddress();

    const LoopbackH2Server = struct {
        listener: *TcpListener,
        tls_config: *tls_mod.ServerTLSConfig,
        accepts: u32 = 0,
        handshakes: u32 = 0,
        stream_ids: [2]u31 = .{ 0, 0 },
        body_lengths: [2]usize = .{ 0, 0 },
        failure: ?anyerror = null,

        const Frame = struct {
            header: http.HTTP2FrameHeader,
            payload: []const u8,
        };

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.failure = err;
            };
        }

        fn readExact(connection: *TLSConnection, buffer: []u8) !void {
            var offset: usize = 0;
            while (offset < buffer.len) {
                const n = try connection.read(buffer[offset..]);
                if (n == 0) return error.UnexpectedEndOfStream;
                offset += n;
            }
        }

        fn readFrame(connection: *TLSConnection, payload_buffer: []u8) !Frame {
            var header_bytes: [9]u8 = undefined;
            try readExact(connection, &header_bytes);
            const header = http.HTTP2FrameHeader.parse(header_bytes);
            const payload_len: usize = @intCast(header.length);
            if (payload_len > payload_buffer.len) return error.FrameTooLarge;
            try readExact(connection, payload_buffer[0..payload_len]);
            return .{ .header = header, .payload = payload_buffer[0..payload_len] };
        }

        fn sendSetting(connection: *TLSConnection, setting: http.HTTP2Settings, value: u32) !void {
            var payload: [6]u8 = undefined;
            mem.writeInt(u16, payload[0..2], @intFromEnum(setting), .big);
            mem.writeInt(u32, payload[2..6], value, .big);
            try writeHTTP2Frame(connection, .settings, 0, 0, &payload);
        }

        fn sendResponse(
            connection: *TLSConnection,
            manager: *h2stream.StreamManager,
            stream_id: u31,
            body: []const u8,
            goaway: bool,
        ) !void {
            var len_buf: [32]u8 = undefined;
            const content_length = try std.fmt.bufPrint(&len_buf, "{d}", .{body.len});
            const headers = [_]hpack.HeaderEntry{
                .{ .name = ":status", .value = "200", .representation = .without_indexing },
                .{ .name = "content-length", .value = content_length, .representation = .without_indexing },
            };
            const header_frames = try h2stream.buildHeadersAndContinuations(
                manager,
                stream_id,
                &headers,
                null,
                16_384,
                false,
                std.heap.page_allocator,
            );
            defer std.heap.page_allocator.free(header_frames);
            try connection.writeAll(header_frames);

            if (goaway) {
                const goaway_payload = try h2stream.buildGoawayPayload(stream_id, .no_error, null, std.heap.page_allocator);
                defer std.heap.page_allocator.free(goaway_payload);
                try writeHTTP2Frame(connection, .goaway, 0, 0, goaway_payload);
                const split = body.len / 2;
                try writeHTTP2Frame(connection, .data, 0, stream_id, body[0..split]);
                try writeHTTP2Frame(connection, .data, 0x01, stream_id, body[split..]);
            } else {
                try writeHTTP2Frame(connection, .data, 0x01, stream_id, body);
            }
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.listener.accept();
            defer accepted.socket.close();
            self.accepts += 1;
            try accepted.socket.setRecvTimeout(30_000);
            try accepted.socket.setSendTimeout(30_000);

            var connection = try tls_mod.acceptServer(
                std.heap.page_allocator,
                &accepted.socket,
                &.{"h2"},
                self.tls_config.*,
            );
            self.handshakes += 1;
            defer connection.closeNotify();
            try std.testing.expectEqualStrings("h2", connection.negotiatedAlpn().?);

            var preface: [http.HTTP2_PREFACE.len]u8 = undefined;
            try readExact(&connection, &preface);
            try std.testing.expectEqualStrings(http.HTTP2_PREFACE, &preface);

            var payload_buffer: [64 * 1024]u8 = undefined;
            const client_settings = try readFrame(&connection, &payload_buffer);
            try std.testing.expectEqual(http.HTTP2FrameType.settings, client_settings.header.frame_type);

            try sendSetting(&connection, .initial_window_size, 70_000);
            try sendSetting(&connection, .max_concurrent_streams, 7);
            const connection_credit = h2stream.buildWindowUpdatePayload(100_000);
            try writeHTTP2Frame(&connection, .window_update, 0, 0, &connection_credit);

            var first_done = false;
            while (!first_done) {
                const frame = try readFrame(&connection, &payload_buffer);
                switch (frame.header.frame_type) {
                    .headers => if (frame.header.stream_id != 0) {
                        self.stream_ids[0] = frame.header.stream_id;
                    },
                    .data => if (frame.header.stream_id == self.stream_ids[0]) {
                        self.body_lengths[0] += frame.payload.len;
                        first_done = (frame.header.flags & 0x01) != 0;
                    },
                    else => {},
                }
            }

            try sendSetting(&connection, .max_frame_size, 32_768);
            const retained_connection_credit = h2stream.buildWindowUpdatePayload(1_000);
            try writeHTTP2Frame(&connection, .window_update, 0, 0, &retained_connection_credit);

            var response_manager = h2stream.StreamManager.init(std.heap.page_allocator, false);
            defer response_manager.deinit();
            try sendResponse(&connection, &response_manager, self.stream_ids[0], "one", false);

            var second_done = false;
            var stream_credit_sent = false;
            while (!second_done) {
                const frame = try readFrame(&connection, &payload_buffer);
                switch (frame.header.frame_type) {
                    .headers => if (frame.header.stream_id != 0) {
                        self.stream_ids[1] = frame.header.stream_id;
                    },
                    .data => if (frame.header.stream_id == self.stream_ids[1]) {
                        self.body_lengths[1] += frame.payload.len;
                        if (!stream_credit_sent and self.body_lengths[1] == 70_000) {
                            const stream_credit = h2stream.buildWindowUpdatePayload(30_000);
                            try writeHTTP2Frame(&connection, .window_update, 0, self.stream_ids[1], &stream_credit);
                            stream_credit_sent = true;
                        }
                        second_done = (frame.header.flags & 0x01) != 0;
                    },
                    else => {},
                }
            }

            try sendResponse(&connection, &response_manager, self.stream_ids[1], "complete-body", true);
            var response_window_updates: usize = 0;
            while (response_window_updates < 4) {
                const frame = try readFrame(&connection, &payload_buffer);
                if (frame.header.frame_type == .window_update) response_window_updates += 1;
            }
        }
    };

    var server = LoopbackH2Server{ .listener = &listener, .tls_config = &tls_config };
    const server_thread = try std.Thread.spawn(.{}, LoopbackH2Server.run, .{&server});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        server_thread.join();
    };

    var client = Client.initWithConfig(allocator, .{
        .verify_ssl = false,
        .http2_enabled = true,
        .keep_alive = true,
        .policy = types.ClientPolicy.embeddingOwned(),
        .timeouts = types.Timeouts.uniform(30_000),
    });
    defer client.deinit();
    const url = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/h2", .{address.getPort()});
    defer allocator.free(url);

    const first_body = try allocator.alloc(u8, 70_000);
    defer allocator.free(first_body);
    @memset(first_body, 'a');
    var first = try client.post(url, .{ .version = .HTTP_2, .body = first_body });
    defer first.deinit();
    try std.testing.expectEqual(types.Version.HTTP_2, first.version);
    try std.testing.expectEqualStrings("one", first.body.?);
    try std.testing.expectEqual(@as(usize, 1), client.poolStats().idle);

    const second_body = try allocator.alloc(u8, 96_000);
    defer allocator.free(second_body);
    @memset(second_body, 'b');
    var second = try client.post(url, .{ .version = .HTTP_2, .body = second_body });
    defer second.deinit();
    try std.testing.expectEqual(types.Version.HTTP_2, second.version);
    try std.testing.expectEqualStrings("complete-body", second.body.?);

    server_thread.join();
    joined = true;
    try std.testing.expect(server.failure == null);
    try std.testing.expectEqual(@as(u32, 1), server.accepts);
    try std.testing.expectEqual(@as(u32, 1), server.handshakes);
    try std.testing.expectEqual(@as(u31, 1), server.stream_ids[0]);
    try std.testing.expectEqual(@as(u31, 3), server.stream_ids[1]);
    try std.testing.expectEqual(@as(usize, first_body.len), server.body_lengths[0]);
    try std.testing.expectEqual(@as(usize, second_body.len), server.body_lengths[1]);
    try std.testing.expectEqual(@as(usize, 0), client.poolStats().total);
}

test "Client stores Set-Cookie headers" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    var response = Response.init(allocator, 200);
    defer response.deinit();

    try response.headers.append("Set-Cookie", "session=abc123; Path=/; HttpOnly");
    try response.headers.append("Set-Cookie", "theme=dark; Path=/");

    try client.storeCookies(&response, "httpbun.com");

    try std.testing.expectEqualStrings("abc123", client.shared.cookies.get("httpbun.com|session").?.value);
    try std.testing.expectEqualStrings("dark", client.shared.cookies.get("httpbun.com|theme").?.value);
}

test "Client attaches Cookie header from jar" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    try client.setCookie("session", "abc123");
    try client.setCookie("theme", "dark");

    var request = try Request.init(allocator, .GET, "http://httpbun.com/");
    defer request.deinit();

    try client.attachCookies(&request);

    const cookie_header = request.headers.get("Cookie") orelse return error.TestUnexpectedResult;
    try std.testing.expect(mem.indexOf(u8, cookie_header, "session=abc123") != null);
    try std.testing.expect(mem.indexOf(u8, cookie_header, "theme=dark") != null);
}

test "Client cookie jar public API" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    try client.setCookie("session", "abc123");
    const value = (try client.getCookie("session")).?;
    defer client.freeCookieValue(value);
    try std.testing.expectEqualStrings("abc123", value);

    const removed = client.removeCookie("session");
    try std.testing.expect(removed);
    try std.testing.expect((try client.getCookie("session")) == null);

    try client.setCookie("theme", "dark");
    try client.setCookie("lang", "en");
    client.clearCookies();
    try std.testing.expectEqual(@as(usize, 0), client.shared.cookies.count());
}

test "Client send/fetch/options aliases" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    // Compile-time alias checks through function pointer assignment.
    const send_ptr: *const fn (*Client, types.Method, []const u8, RequestOptions) anyerror!Response = Client.send;
    const fetch_ptr: *const fn (*Client, []const u8, RequestOptions) anyerror!Response = Client.fetch;
    const del_ptr: *const fn (*Client, []const u8, RequestOptions) anyerror!Response = Client.del;
    const trace_ptr: *const fn (*Client, []const u8, RequestOptions) anyerror!Response = Client.trace;
    const connect_ptr: *const fn (*Client, []const u8, RequestOptions) anyerror!Response = Client.connect;
    const options_ptr: *const fn (*Client, []const u8, RequestOptions) anyerror!Response = Client.options;
    const opts_ptr: *const fn (*Client, []const u8, RequestOptions) anyerror!Response = Client.opts;
    _ = send_ptr;
    _ = fetch_ptr;
    _ = del_ptr;
    _ = trace_ptr;
    _ = connect_ptr;
    _ = options_ptr;
    _ = opts_ptr;
}

test "Client hasCookie and cookieCount" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    try std.testing.expectEqual(@as(usize, 0), client.cookieCount());
    try std.testing.expect(!client.hasCookie("session"));

    try client.setCookie("session", "abc123");
    try std.testing.expectEqual(@as(usize, 1), client.cookieCount());
    try std.testing.expect(client.hasCookie("session"));
}

test "Client pool helpers" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    client.cleanupIdleConnections();
    const stats = client.poolStats();
    try std.testing.expectEqual(@as(usize, 0), stats.total);
    try std.testing.expectEqual(@as(usize, 0), stats.active);
    try std.testing.expectEqual(@as(usize, 0), stats.idle);
    try std.testing.expectEqual(@as(usize, 0), client.hostPoolConnectionCount("httpbun.com", 443));
}

test "Client retry classifier avoids TLS/protocol retries" {
    try std.testing.expect(!Client.isRetryableRequestError(error.TLSConnectionTruncated));
    try std.testing.expect(!Client.isRetryableRequestError(error.InvalidResponse));
    try std.testing.expect(!Client.isRetryableRequestError(error.ProtocolError));
    try std.testing.expect(!Client.isRetryableRequestError(error.Cancelled));
    try std.testing.expect(!Client.isRetryableRequestError(error.RequestTimeout));
    try std.testing.expect(Client.isRetryableRequestError(error.ConnectionReset));
}

test "Client retry wait maps cancellation and request deadline" {
    var token = types.CancellationToken.init();
    token.cancel();
    const cancelled = IoContext.init(.{ .external_cancel = &token });
    try std.testing.expectError(error.Cancelled, Client.waitForRetry(&cancelled, 1_000));

    const expired = IoContext.init(.{ .request_deadline = Deadline.at(0) });
    try std.testing.expectError(error.RequestTimeout, Client.waitForRetry(&expired, 1_000));
}

test "Client observes an already-cancelled borrowed token before request setup" {
    var client = Client.init(std.testing.allocator);
    defer client.deinit();

    var token = types.CancellationToken.init();
    token.cancel();

    try std.testing.expectError(
        error.Cancelled,
        client.request(.GET, "not-a-valid-url", .{ .cancel_token = &token }),
    );
}

test "Client proxy request formatting" {
    const allocator = std.testing.allocator;
    var client = Client.initWithConfig(allocator, .{});
    defer client.deinit();

    var req = try Request.init(allocator, .GET, "http://httpbun.com/api/v1/users?active=true");
    defer req.deinit();
    try req.headers.set("Accept", "application/json");

    const formatted = try client.formatProxyRequest(&req, .{
        .host = "127.0.0.1",
        .port = 8080,
        .username = "user",
        .password = "pass",
    });
    defer allocator.free(formatted);

    try std.testing.expect(std.mem.indexOf(u8, formatted, "GET http://httpbun.com:80/api/v1/users?active=true HTTP/1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "Accept: application/json\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") != null);
}

test "Client multipart options and MIME resolution" {
    const allocator = std.testing.allocator;

    var client = Client.init(allocator);
    defer client.deinit();

    const fields = [_]MultipartField{
        .{ .name = "username", .value = "bob" },
    };
    const files = [_]MultipartFile{
        .{ .name = "doc", .filename = "notes.html", .data = "some content", .content_type = null },
        .{ .name = "custom", .filename = "data.bin", .data = "binary data", .content_type = "application/x-custom" },
    };

    var req = try Request.init(allocator, .POST, "http://localhost/");
    defer req.deinit();

    const reqOpts = RequestOptions.defaults()
        .withMultipartFields(&fields)
        .withMultipartFiles(&files);

    if (reqOpts.multipart_fields != null or reqOpts.multipart_files != null) {
        const boundary = reqOpts.multipart_boundary orelse "----httpxBoundary1234567890";
        var builder = @import("../data/multipart.zig").MultipartBuilder.init(allocator, boundary);
        defer builder.deinit();

        if (reqOpts.multipart_fields) |flds| {
            for (flds) |field| {
                try builder.addField(field.name, field.value);
            }
        }

        if (reqOpts.multipart_files) |fls| {
            for (fls) |file| {
                const resolved_mime = file.content_type orelse common.mimeTypeFromPathOr(file.filename, "application/octet-stream");
                try builder.addFile(file.name, file.filename, resolved_mime, file.data);
            }
        }

        const body = try builder.build();
        defer allocator.free(body);
        try req.setBody(body);

        const ct = try builder.contentType();
        defer allocator.free(ct);
        try req.headers.set(HeaderName.CONTENT_TYPE, ct);
    }

    try std.testing.expect(req.body != null);
    try std.testing.expect(std.mem.indexOf(u8, req.body.?, "text/html; charset=utf-8") != null);
    try std.testing.expect(std.mem.indexOf(u8, req.body.?, "application/x-custom") != null);
    try std.testing.expect(std.mem.indexOf(u8, req.body.?, "name=\"username\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req.body.?, "bob") != null);

    const ct = req.headers.get("Content-Type").?;
    try std.testing.expect(std.mem.startsWith(u8, ct, "multipart/form-data; boundary=----httpxBoundary1234567890"));
}

test "RequestOptions per-request overrides" {
    const proxy = types.Proxy{
        .kind = .http,
        .host = "127.0.0.1",
        .port = 8888,
        .username = null,
        .password = null,
    };

    const opts = RequestOptions.defaults()
        .withProxy(proxy)
        .withSslVerification(false)
        .withKeepAlive(false)
        .withUnixSocket("/tmp/test.sock");

    try std.testing.expect(opts.proxy != null);
    try std.testing.expectEqualStrings("127.0.0.1", opts.proxy.?.host);
    try std.testing.expectEqual(@as(u16, 8888), opts.proxy.?.port);
    try std.testing.expectEqual(false, opts.verify_ssl.?);
    try std.testing.expectEqual(false, opts.keep_alive.?);
    try std.testing.expectEqualStrings("/tmp/test.sock", opts.unix_socket_path.?);
}

test "RequestOptions explicit timeout resolution" {
    const allocator = std.testing.allocator;
    var client = Client.initWithConfig(allocator, .{
        .timeouts = .{
            .connect_ms = 5000,
            .read_ms = 10000,
            .write_ms = 15000,
        },
    });
    defer client.deinit();

    // Default fallback
    const t_def = client.resolveRequestTimeouts(.{});
    try std.testing.expectEqual(@as(u64, 5000), t_def.connect_ms);
    try std.testing.expectEqual(@as(u64, 10000), t_def.read_ms);
    try std.testing.expectEqual(@as(u64, 15000), t_def.write_ms);

    // Uniform timeout_ms override
    const t_uni = client.resolveRequestTimeouts(RequestOptions.defaults().withTimeoutMs(2000));
    try std.testing.expectEqual(@as(u64, 2000), t_uni.connect_ms);
    try std.testing.expectEqual(@as(u64, 2000), t_uni.read_ms);
    try std.testing.expectEqual(@as(u64, 2000), t_uni.write_ms);

    // Explicit per-phase timeout overrides
    const t_exp = client.resolveRequestTimeouts(
        RequestOptions.defaults()
            .withConnectTimeoutMs(100)
            .withReadTimeoutMs(200)
            .withWriteTimeoutMs(300),
    );
    try std.testing.expectEqual(@as(u64, 100), t_exp.connect_ms);
    try std.testing.expectEqual(@as(u64, 200), t_exp.read_ms);
    try std.testing.expectEqual(@as(u64, 300), t_exp.write_ms);

    // Explicit timeouts struct override
    const t_struct = client.resolveRequestTimeouts(
        RequestOptions.defaults().withTimeouts(.{
            .connect_ms = 111,
            .read_ms = 222,
            .write_ms = 333,
        }),
    );
    try std.testing.expectEqual(@as(u64, 111), t_struct.connect_ms);
    try std.testing.expectEqual(@as(u64, 222), t_struct.read_ms);
    try std.testing.expectEqual(@as(u64, 333), t_struct.write_ms);
}

test "Cookie path matching" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    // Test pathMatches helper
    try std.testing.expect(Client.pathMatches("/", "/"));
    try std.testing.expect(Client.pathMatches("/api/users", "/api"));
    try std.testing.expect(Client.pathMatches("/api/users", "/api/"));
    try std.testing.expect(Client.pathMatches("/api/users", "/"));
    try std.testing.expect(!Client.pathMatches("/api", "/api/users"));
    try std.testing.expect(!Client.pathMatches("/other", "/api"));
}

test "Cookie domain matching" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    try std.testing.expect(Client.domainMatches("example.com", "example.com"));
    try std.testing.expect(Client.domainMatches("www.example.com", "example.com"));
    try std.testing.expect(Client.domainMatches("www.example.com", ".example.com"));
    try std.testing.expect(!Client.domainMatches("example.com", "other.com"));
    try std.testing.expect(!Client.domainMatches("notexample.com", "example.com"));
}

test "CookieEntry stores metadata" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator);
    defer client.deinit();

    try client.setCookie("session", "abc123");
    const entry = client.shared.cookies.get("session").?;
    try std.testing.expectEqualStrings("abc123", entry.value);
    try std.testing.expectEqualStrings("/", entry.path);
    try std.testing.expect(!entry.secure);
}

test "RequestOptions withRange" {
    const opts = RequestOptions.defaults().withRange("bytes=0-499");
    try std.testing.expectEqualStrings("bytes=0-499", opts.range_header.?);
}

test "RequestOptions withByteRange" {
    const opts = RequestOptions.defaults().withByteRange(0, 499);
    try std.testing.expectEqualStrings("bytes=0-499", opts.range_header.?);
}

test "RequestOptions withSuffixRange" {
    const opts = RequestOptions.defaults().withSuffixRange(500);
    try std.testing.expectEqualStrings("bytes=-500", opts.range_header.?);
}

test "RequestOptions withApiKey" {
    const opts = RequestOptions.defaults().withApiKey("X-API-Key", "my-secret-key");
    try std.testing.expectEqualStrings("X-API-Key", opts.api_key_header.?);
    try std.testing.expectEqualStrings("my-secret-key", opts.api_key_value.?);
}

test "RequestOptions withExpect100Continue" {
    const opts = RequestOptions.defaults().withExpect100Continue();
    try std.testing.expect(opts.expect_100_continue);
}

test "Interceptor error_fn callback type" {
    const TestContext = struct {
        var called: bool = false;
        var last_err: anyerror = undefined;
    };
    const onError = struct {
        fn f(err: anyerror, _: *const AttemptContext, ctx: ?*anyopaque) void {
            _ = ctx;
            TestContext.called = true;
            TestContext.last_err = err;
        }
    }.f;
    var interceptor = Interceptor{};
    interceptor.error_fn = onError;
    try std.testing.expect(interceptor.error_fn != null);
    const attempt = AttemptContext{
        .logical_request_id = 1,
        .attempt = 1,
        .redirect_count = 0,
        .policy = types.ClientPolicy.managed().resolve(.{}),
        .url = "https://example.com",
    };
    interceptor.error_fn.?(error.ConnectionRefused, &attempt, null);
    try std.testing.expect(TestContext.called);
    try std.testing.expectEqualStrings("ConnectionRefused", @errorName(TestContext.last_err));
}

test "Interceptor retry_fn callback type" {
    const TestContext = struct {
        var called: bool = false;
        var last_attempt: u32 = 0;
    };
    const onRetry = struct {
        fn f(attempt: *const AttemptContext, ctx: ?*anyopaque) void {
            _ = ctx;
            TestContext.called = true;
            TestContext.last_attempt = attempt.attempt;
        }
    }.f;
    var interceptor = Interceptor{};
    interceptor.retry_fn = onRetry;
    try std.testing.expect(interceptor.retry_fn != null);
    const attempt = AttemptContext{
        .logical_request_id = 1,
        .attempt = 3,
        .redirect_count = 0,
        .policy = types.ClientPolicy.managed().resolve(.{}),
        .url = "https://example.com",
    };
    interceptor.retry_fn.?(&attempt, null);
    try std.testing.expect(TestContext.called);
    try std.testing.expectEqual(@as(u32, 3), TestContext.last_attempt);
}

test "Interceptor redirect_fn callback type" {
    const TestContext = struct {
        var called: bool = false;
        var last_url: []const u8 = "";
    };
    const onRedirect = struct {
        fn f(url: []const u8, _: *const AttemptContext, ctx: ?*anyopaque) void {
            _ = ctx;
            TestContext.called = true;
            TestContext.last_url = url;
        }
    }.f;
    var interceptor = Interceptor{};
    interceptor.redirect_fn = onRedirect;
    try std.testing.expect(interceptor.redirect_fn != null);
    const attempt = AttemptContext{
        .logical_request_id = 1,
        .attempt = 1,
        .redirect_count = 0,
        .policy = types.ClientPolicy.managed().resolve(.{}),
        .url = "https://example.com",
    };
    interceptor.redirect_fn.?("https://example.com/new", &attempt, null);
    try std.testing.expect(TestContext.called);
    try std.testing.expectEqualStrings("https://example.com/new", TestContext.last_url);
}

test "Client custom log_fn receives messages" {
    const TestLogger = struct {
        var logged: bool = false;
        var last_level: server_mod.LogLevel = .debug;
        var last_message: []const u8 = "";

        fn log_fn(level: server_mod.LogLevel, message: []const u8) void {
            logged = true;
            last_level = level;
            last_message = message;
        }
    };

    var client = Client.initWithConfig(std.testing.allocator, .{
        .log_fn = TestLogger.log_fn,
    });
    defer client.deinit();

    client.log(.info, "connection to {s}:{d}", .{ "example.com", 443 });
    try std.testing.expect(TestLogger.logged);
    try std.testing.expectEqual(server_mod.LogLevel.info, TestLogger.last_level);
    try std.testing.expect(std.mem.indexOf(u8, TestLogger.last_message, "example.com") != null);
}

test "Client without log_fn silently drops messages" {
    var client = Client.initWithConfig(std.testing.allocator, .{
        .log_fn = null,
    });
    defer client.deinit();

    client.log(.info, "this should be silently dropped {s}", .{"test"});
}

test "Client log_level filters messages below threshold" {
    const TestLogger = struct {
        var logged: bool = false;

        fn log_fn(level: server_mod.LogLevel, message: []const u8) void {
            _ = level;
            _ = message;
            logged = true;
        }
    };

    var client = Client.initWithConfig(std.testing.allocator, .{
        .log_fn = TestLogger.log_fn,
        .log_level = .warn,
    });
    defer client.deinit();

    client.log(.debug, "debug message", .{});
    try std.testing.expect(!TestLogger.logged);

    client.log(.info, "info message", .{});
    try std.testing.expect(!TestLogger.logged);

    client.log(.warn, "warn message", .{});
    try std.testing.expect(TestLogger.logged);
}
