const std = @import("std");
const client_mod = @import("client.zig");
const Client = client_mod.Client;
const types = @import("../core/types.zig");
const Uri = @import("../core/uri.zig").Uri;
const Request = @import("../core/request.zig").Request;
const net = @import("../net/socket.zig");
const address = @import("../net/address.zig");
const dns = @import("../net/dns.zig");
const unix = @import("../net/unix.zig");
const context_mod = @import("../io/context.zig");
const IoContext = context_mod.IoContext;
const Deadline = context_mod.Deadline;

const Capture = struct {
    writes: usize = 0,
    reads: usize = 0,
    selected_url: ?[]const u8 = null,
    last_error: ?anyerror = null,
    response: []const u8 = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",

    fn write(ptr: *anyopaque, bytes: []const u8) !usize {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        self.writes += 1;
        return bytes.len;
    }

    fn read(ptr: *anyopaque, output: []u8) !usize {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        const n = @min(output.len, self.response.len - self.reads);
        @memcpy(output[0..n], self.response[self.reads..][0..n]);
        self.reads += n;
        return n;
    }

    fn selectHost(req: *Request, _: *const client_mod.AttemptContext, ptr: ?*anyopaque) !void {
        const self: *@This() = @ptrCast(@alignCast(ptr.?));
        if (self.selected_url) |url| {
            req.uri = try Uri.parse(url);
            try req.headers.set("Host", req.uri.host.?);
        }
    }

    fn observeError(err: anyerror, _: *const client_mod.AttemptContext, ptr: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(ptr.?));
        self.last_error = err;
    }
};

fn complete(client: *Client, url: []const u8, buffered: bool, strict: bool, proxy: ?types.Proxy) !void {
    if (buffered) {
        var response = try client.get(url, .{ .require_interruptible_dns = strict, .proxy = proxy });
        defer response.deinit();
        try std.testing.expectEqual(@as(u16, 200), response.status.code);
    } else {
        var op = try client.open(.GET, url, .{ .require_interruptible_dns = strict, .proxy = proxy });
        defer op.deinit();
        const head = try op.finishRequest(null);
        try std.testing.expectEqual(@as(u16, 200), head.status.code);
        try op.finish(.{});
    }
}

test "streaming strict DNS uses final interceptor no_proxy and proxy route for both APIs" {
    const Case = struct {
        url: []const u8,
        selected_url: ?[]const u8 = null,
        proxy: ?types.Proxy = null,
        override: ?types.Proxy = null,
        allowed: bool,
    };
    const cases = [_]Case{
        .{ .url = "http://native.invalid/", .allowed = false },
        .{ .url = "http://127.0.0.1/", .allowed = true },
        .{ .url = "http://[::1]/", .allowed = true },
        .{ .url = "http://127.0.0.1/", .selected_url = "http://native.invalid/final", .allowed = false },
        .{ .url = "http://native.invalid/", .selected_url = "http://127.0.0.1/final", .allowed = true },
        .{ .url = "http://127.0.0.1/", .proxy = .{ .host = "proxy.invalid", .port = 80 }, .allowed = false },
        .{ .url = "http://native.invalid/", .proxy = .{ .host = "127.0.0.1", .port = 80 }, .allowed = true },
        .{ .url = "http://original.invalid/", .selected_url = "http://native.invalid/final", .proxy = .{ .host = "127.0.0.1", .port = 80, .no_proxy = "native.invalid" }, .allowed = false },
        .{ .url = "http://original.invalid/", .selected_url = "http://127.0.0.1/final", .proxy = .{ .host = "proxy.invalid", .port = 80, .no_proxy = "127.0.0.1" }, .allowed = true },
        .{ .url = "http://native.invalid/", .proxy = .{ .host = "proxy.invalid", .port = 80 }, .override = .{ .host = "127.0.0.1", .port = 80 }, .allowed = true },
        .{ .url = "http://native.invalid/", .proxy = .{ .host = "127.0.0.1", .port = 80 }, .override = .{ .host = "proxy.invalid", .port = 80 }, .allowed = false },
    };
    for (cases) |case| {
        for ([_]bool{ false, true }) |buffered| {
            var capture = Capture{ .selected_url = case.selected_url };
            var adapter = client_mod.TransportAdapter{ .context = &capture, .writeFn = Capture.write, .readFn = Capture.read };
            var client = try Client.tryInitWithConfig(std.testing.allocator, .{
                .transport_adapter = &adapter,
                .proxy = case.proxy,
                .policy = types.ClientPolicy.embeddingOwned(),
            });
            defer client.deinit();
            try client.addInterceptor(.{ .request_fn = Capture.selectHost, .error_fn = Capture.observeError, .context = &capture });
            if (case.allowed) {
                try complete(&client, case.url, buffered, true, case.override);
                try std.testing.expect(capture.writes > 0);
                try std.testing.expect(capture.last_error == null);
            } else {
                try std.testing.expectError(error.SystemDnsCancellationUnsupported, complete(&client, case.url, buffered, true, case.override));
                try std.testing.expectEqual(@as(usize, 0), capture.writes);
                try std.testing.expectEqual(error.SystemDnsCancellationUnsupported, capture.last_error.?);
            }
            try std.testing.expectEqual(@as(usize, 0), client.poolStats().total);
        }
    }
}

test "streaming strict DNS defaults preserve non-strict operation and buffered behavior" {
    try std.testing.expect(!(client_mod.OpenOptions{}).require_interruptible_dns);
    try std.testing.expect(!(client_mod.RequestOptions{}).require_interruptible_dns);
    try std.testing.expectEqual(address.SystemDnsCancellation.completion_only, address.system_dns_cancellation);
    for ([_]bool{ false, true }) |buffered| {
        var capture = Capture{};
        var adapter = client_mod.TransportAdapter{ .context = &capture, .writeFn = Capture.write, .readFn = Capture.read };
        var client = try Client.tryInitWithConfig(std.testing.allocator, .{
            .transport_adapter = &adapter,
            .policy = types.ClientPolicy.embeddingOwned(),
        });
        defer client.deinit();
        try complete(&client, "http://native.invalid/", buffered, false, null);
        try std.testing.expect(capture.writes > 0);
    }
}

test "streaming strict DNS denial cleans up every allocation failure" {
    const Case = struct {
        fn run(allocator: std.mem.Allocator, buffered: bool) !void {
            var client = try Client.tryInitWithConfig(allocator, .{ .policy = types.ClientPolicy.embeddingOwned() });
            defer client.deinit();
            complete(&client, "http://native.invalid/", buffered, true, null) catch |err| {
                if (err == error.SystemDnsCancellationUnsupported) {
                    try std.testing.expectEqual(@as(usize, 0), client.poolStats().total);
                    return;
                }
                return err;
            };
            return error.TestUnexpectedResult;
        }
    };
    for ([_]bool{ false, true }) |buffered| {
        try std.testing.checkAllAllocationFailures(std.testing.allocator, Case.run, .{buffered});
    }
}

test "streaming strict DNS stays enabled across buffered redirects" {
    var capture = Capture{ .response = "HTTP/1.1 302 Found\r\nLocation: http://native.invalid/final\r\nContent-Length: 0\r\n\r\n" };
    var adapter = client_mod.TransportAdapter{ .context = &capture, .writeFn = Capture.write, .readFn = Capture.read };
    var policy = types.ClientPolicy.embeddingOwned();
    policy.redirect = .{ .policy = .{ .allow_cross_origin = true } };
    var client = try Client.tryInitWithConfig(std.testing.allocator, .{ .transport_adapter = &adapter, .policy = policy });
    defer client.deinit();
    try std.testing.expectError(error.SystemDnsCancellationUnsupported, client.get("http://127.0.0.1/first", .{ .require_interruptible_dns = true }));
    try std.testing.expectEqual(@as(usize, 1), capture.writes);
}

fn waitReadable(socket: *net.Socket, context: *const IoContext) !void {
    while (!socket.waitReadable(10)) try context.check();
    try context.check();
}

fn readExact(socket: *net.Socket, bytes: []u8, context: *const IoContext) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = try socket.recvWithContext(bytes[offset..], context);
        if (n == 0) return error.UnexpectedEof;
        offset += n;
    }
}

const HttpFixture = struct {
    listener: *net.Socket,
    connections: usize = 1,
    requests_per_connection: usize = 2,
    accepted: usize = 0,
    stop: types.CancellationToken = .{},
    failure: ?anyerror = null,

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            if (err != error.Cancelled) self.failure = err;
        };
    }

    fn serve(self: *@This()) !void {
        const context = IoContext.init(.{ .external_cancel = &self.stop, .request_deadline = Deadline.afterMs(5000) });
        for (0..self.connections) |_| {
            try waitReadable(self.listener, &context);
            var accepted = try self.listener.accept();
            defer accepted.socket.close();
            self.accepted += 1;
            for (0..self.requests_per_connection) |_| {
                var head: [4096]u8 = undefined;
                var length: usize = 0;
                while (!std.mem.endsWith(u8, head[0..length], "\r\n\r\n")) {
                    if (length == head.len) return error.HeaderTooLarge;
                    try readExact(&accepted.socket, head[length..][0..1], &context);
                    length += 1;
                }
                try accepted.socket.sendAllWithContext("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", &context);
            }
        }
    }
};

const DnsFixture = struct {
    tcp: net.TcpListener,
    udp: net.UdpSocket,
    fallback: bool,
    stall: bool,
    arrived: std.atomic.Value(bool) = .init(false),
    stop: types.CancellationToken = .{},
    failure: ?anyerror = null,

    fn init(fallback: bool, stall: bool) !@This() {
        var tcp = try net.TcpListener.init(try address.Address.parseIp("127.0.0.1", 0));
        errdefer tcp.deinit();
        var udp = try net.UdpSocket.create();
        errdefer udp.close();
        try udp.bind(try tcp.getLocalAddress());
        try udp.setRecvTimeout(1000);
        return .{ .tcp = tcp, .udp = udp, .fallback = fallback, .stall = stall };
    }

    fn deinit(self: *@This()) void {
        self.udp.close();
        self.tcp.deinit();
    }

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            if (err != error.Cancelled) self.failure = err;
        };
    }

    fn reply(query: []const u8, output: []u8, truncated: bool) ![]const u8 {
        if (query.len < 12) return error.InvalidDnsFixtureQuery;
        var end: usize = 12;
        while (end < query.len and query[end] != 0) end += 1 + @as(usize, query[end]);
        end += 5;
        if (end > query.len or end + 16 > output.len) return error.InvalidDnsFixtureQuery;
        if (!std.mem.eql(u8, query[12 .. end - 4], "\x06strict\x04test\x00")) return error.InvalidDnsFixtureQuery;
        @memcpy(output[0..end], query[0..end]);
        output[2..12].* = .{ if (truncated) 0x83 else 0x81, 0x80, 0, 1, 0, if (truncated) 0 else 1, 0, 0, 0, 0 };
        if (truncated) return output[0..end];
        @memcpy(output[end..][0..16], "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01");
        return output[0 .. end + 16];
    }

    fn serve(self: *@This()) !void {
        const context = IoContext.init(.{ .external_cancel = &self.stop, .request_deadline = Deadline.afterMs(5000) });
        var borrowed_udp = net.Socket.fromHandle(self.udp.handle);
        try waitReadable(&borrowed_udp, &context);
        var query: [512]u8 = undefined;
        const received = try self.udp.recvFrom(&query);
        var output: [512]u8 = undefined;
        if (self.fallback) {
            const truncated = try reply(query[0..received.n], &output, true);
            if (try self.udp.sendTo(received.addr, truncated) != truncated.len) return error.ShortDatagram;
            try waitReadable(&self.tcp.socket, &context);
            var accepted = try self.tcp.accept();
            defer accepted.socket.close();
            var prefix: [2]u8 = undefined;
            try readExact(&accepted.socket, &prefix, &context);
            const length = std.mem.readInt(u16, &prefix, .big);
            if (length > query.len) return error.InvalidDnsFixtureQuery;
            try readExact(&accepted.socket, query[0..length], &context);
            self.arrived.store(true, .release);
            if (self.stall) {
                while (true) try context.waitForMs(10);
            }
            const response = try reply(query[0..length], &output, false);
            std.mem.writeInt(u16, &prefix, @intCast(response.len), .big);
            try accepted.socket.sendAllWithContext(&prefix, &context);
            try accepted.socket.sendAllWithContext(response, &context);
        } else {
            self.arrived.store(true, .release);
            if (self.stall) {
                while (true) try context.waitForMs(10);
            }
            const response = try reply(query[0..received.n], &output, false);
            if (try self.udp.sendTo(received.addr, response) != response.len) return error.ShortDatagram;
        }
    }
};

test "streaming strict DNS resolves real direct proxy UDP TCP routes and reuses connections" {
    const cases = [_]struct { fallback: bool, proxy: bool }{
        .{ .fallback = false, .proxy = false },
        .{ .fallback = true, .proxy = false },
        .{ .fallback = false, .proxy = true },
        .{ .fallback = true, .proxy = true },
    };
    for (cases) |case| {
        const fallback = case.fallback;
        var fixture = try DnsFixture.init(fallback, false);
        defer fixture.deinit();
        const thread = try std.Thread.spawn(.{}, DnsFixture.run, .{&fixture});
        var dns_joined = false;
        defer if (!dns_joined) {
            fixture.stop.cancel();
            thread.join();
        };
        const servers = [_]dns.DnsServer{.{ .ip = "127.0.0.1", .port = try fixture.tcp.getLocalPort() }};
        var resolver = dns.DNSResolver.init(std.testing.allocator, .{
            .dns_servers = &servers,
            .address_family = .ipv4_only,
            .cache_enabled = false,
        });
        defer resolver.deinit();
        var listener = try net.TcpListener.init(try address.Address.parseIp("127.0.0.1", 0));
        defer listener.deinit();
        var http = HttpFixture{ .listener = &listener.socket };
        const http_thread = try std.Thread.spawn(.{}, HttpFixture.run, .{&http});
        var http_joined = false;
        defer if (!http_joined) {
            http.stop.cancel();
            http_thread.join();
        };
        var client = try Client.tryInitWithConfig(std.testing.allocator, .{
            .dns_resolver = &resolver,
            .proxy = if (case.proxy) .{ .host = "strict.test", .port = try listener.getLocalPort() } else null,
            .policy = types.ClientPolicy.embeddingOwned(),
            .timeouts = types.Timeouts.uniform(2000),
        });
        defer client.deinit();
        var url_buffer: [128]u8 = undefined;
        const url = if (case.proxy) "http://origin.invalid/qualified" else try std.fmt.bufPrint(&url_buffer, "http://strict.test:{d}/qualified", .{try listener.getLocalPort()});
        try complete(&client, url, false, true, null);
        try complete(&client, url, true, true, null);
        thread.join();
        dns_joined = true;
        http_thread.join();
        http_joined = true;
        try std.testing.expect(fixture.failure == null);
        try std.testing.expect(http.failure == null);
        try std.testing.expectEqual(@as(usize, 1), http.accepted);
        try std.testing.expect(fixture.arrived.load(.acquire));
        try std.testing.expectEqual(@as(u64, 1), resolver.getStats().udp_queries);
        try std.testing.expectEqual(@as(u64, if (fallback) 1 else 0), resolver.getStats().tcp_queries);
    }
}

test "streaming strict DNS interrupts actual configured UDP and TCP waits" {
    for ([_]bool{ false, true }) |fallback| {
        for ([_]bool{ false, true }) |cancel| {
            var fixture = try DnsFixture.init(fallback, true);
            defer fixture.deinit();
            const thread = try std.Thread.spawn(.{}, DnsFixture.run, .{&fixture});
            var dns_joined = false;
            defer if (!dns_joined) {
                fixture.stop.cancel();
                thread.join();
            };
            const servers = [_]dns.DnsServer{.{ .ip = "127.0.0.1", .port = try fixture.tcp.getLocalPort() }};
            var resolver = dns.DNSResolver.init(std.testing.allocator, .{
                .dns_servers = &servers,
                .address_family = .ipv4_only,
                .cache_enabled = false,
                .udp_timeout_ms = 5000,
                .tcp_timeout_ms = 5000,
            });
            defer resolver.deinit();
            var client = try Client.tryInitWithConfig(std.testing.allocator, .{
                .dns_resolver = &resolver,
                .policy = types.ClientPolicy.embeddingOwned(),
            });
            defer client.deinit();
            var token = types.CancellationToken.init();
            const Worker = struct {
                client: *Client,
                token: *types.CancellationToken,
                cancel: bool,
                failure: ?anyerror = null,
                fn run(self: *@This()) void {
                    var op = self.client.open(.GET, "http://strict.test:1/", .{
                        .require_interruptible_dns = true,
                        .cancel_token = self.token,
                        .connect_timeout_ms = if (self.cancel) 2000 else 150,
                    }) catch |err| {
                        self.failure = err;
                        return;
                    };
                    op.deinit();
                    self.failure = error.TestUnexpectedResult;
                }
            };
            var worker = Worker{ .client = &client, .token = &token, .cancel = cancel };
            const started = context_mod.monotonicNowNs();
            const worker_thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
            var joined = false;
            defer if (!joined) {
                token.cancel();
                worker_thread.join();
            };
            const wait = IoContext.init(.{ .request_deadline = Deadline.afterMs(1000) });
            while (!fixture.arrived.load(.acquire)) try wait.waitForMs(1);
            if (cancel) token.cancel();
            worker_thread.join();
            joined = true;
            fixture.stop.cancel();
            thread.join();
            dns_joined = true;
            try std.testing.expect(fixture.failure == null);
            try std.testing.expectEqual(if (cancel) error.Cancelled else error.Timeout, worker.failure.?);
            try std.testing.expect(context_mod.monotonicNowNs() - started < std.time.ns_per_s);
            try std.testing.expectEqual(@as(usize, 0), client.poolStats().total);
        }
    }
}

test "streaming strict DNS exempts Unix but preserves protocol rejection without TCP fallback" {
    var path_buffer: [96]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "httpx-strict-unix-{d}.sock", .{context_mod.monotonicNowNs()});
    var listener = try unix.UnixListener.init(path);
    defer listener.deinit();
    var borrowed = net.Socket.fromHandle(listener.fd);
    var sentinel = try net.TcpListener.init(try address.Address.parseIp("127.0.0.1", 0));
    defer sentinel.deinit();
    var url_buffer: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buffer, "http://127.0.0.1:{d}/unix", .{try sentinel.getLocalPort()});
    const cases = [_]struct { h2: bool = false, h3: bool = false, version: ?types.Version = null, tls: bool = false }{
        .{ .h2 = true },
        .{ .version = .HTTP_2 },
        .{ .h3 = true },
        .{ .version = .HTTP_3 },
        .{ .tls = true },
    };
    for (cases) |case| {
        var client = try Client.tryInitWithConfig(std.testing.allocator, .{
            .unix_socket_path = path,
            .http2_enabled = case.h2,
            .http3_enabled = case.h3,
            .policy = types.ClientPolicy.embeddingOwned(),
        });
        defer client.deinit();
        const target = if (case.tls) "https://native.invalid/unix" else url;
        const expected = if (case.h3 or case.version == .HTTP_3) error.UnsupportedHttpVersion else error.UnsupportedStreamingTransport;
        try std.testing.expectError(expected, client.open(.GET, target, .{ .version = case.version, .require_interruptible_dns = true }));
        try std.testing.expectError(expected, client.get(target, .{ .version = case.version, .require_interruptible_dns = true }));
        try std.testing.expect(!sentinel.socket.waitReadable(0));
        try std.testing.expect(!borrowed.waitReadable(0));
    }
    var http = HttpFixture{ .listener = &borrowed, .connections = 2, .requests_per_connection = 1 };
    const thread = try std.Thread.spawn(.{}, HttpFixture.run, .{&http});
    var joined = false;
    defer if (!joined) {
        http.stop.cancel();
        thread.join();
    };
    var client = try Client.tryInitWithConfig(std.testing.allocator, .{
        .unix_socket_path = path,
        .policy = types.ClientPolicy.embeddingOwned(),
        .timeouts = types.Timeouts.uniform(2000),
    });
    defer client.deinit();
    try complete(&client, "http://native.invalid/unix", false, true, null);
    try complete(&client, "http://native.invalid/unix", true, true, null);
    thread.join();
    joined = true;
    try std.testing.expect(http.failure == null);
    try std.testing.expectEqual(@as(usize, 2), http.accepted);
    try std.testing.expect(!sentinel.socket.waitReadable(0));
}
