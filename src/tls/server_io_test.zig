const std = @import("std");
const testing = std.testing;
const engine = @import("tls.zig");
const net = @import("../net/socket.zig");
const context_mod = @import("../io/context.zig");
const IoContext = context_mod.IoContext;
const Deadline = context_mod.Deadline;
const p = @import("crypto/provider.zig");
const fixtures = @import("trust_fixtures.zig");
const Version = std.crypto.tls.ProtocolVersion;
const AtomicBool = std.atomic.Value(bool);

const Pair = struct {
    peer: net.Socket,
    accepted: net.Socket,

    fn init() !Pair {
        var listener = try net.TcpListener.init(try @import("../net/compat.zig").Address.parseIp("127.0.0.1", 0));
        defer listener.deinit();
        var peer = try net.Socket.create();
        errdefer peer.close();
        try peer.connectWithTimeout(try listener.getLocalAddress(), 2_000);
        if (!listener.socket.waitReadable(2_000)) return error.FixtureAcceptTimeout;
        var accepted = try listener.accept();
        errdefer accepted.socket.close();
        try peer.setRecvTimeout(2_000);
        try peer.setSendTimeout(2_000);
        try accepted.socket.setRecvTimeout(2_000);
        try accepted.socket.setSendTimeout(2_000);
        return .{ .peer = peer, .accepted = accepted.socket };
    }

    fn deinit(self: *Pair) void {
        self.peer.close();
        self.accepted.close();
    }
};

const Observed = struct {
    standard: engine.StandardCryptoProvider,
    version: Version = .tls_1_3,
    parent: *IoContext,
    armed: bool = false,
    entered: AtomicBool = .init(false),
    cancel_finished: bool = false,
    finished_checks: usize = 0,

    fn owner(context: *anyopaque) *@This() {
        const standard: *engine.StandardCryptoProvider = @ptrCast(@alignCast(context));
        return @fieldParentPtr("standard", standard);
    }

    fn capabilities(context: *anyopaque) p.Capabilities {
        const self = owner(context);
        var caps = self.standard.provider().vtable.capabilities(context);
        caps.kems = 0;
        if (self.version == .tls_1_2) caps.hkdf_hashes = 0;
        if (self.armed) self.entered.store(true, .release);
        return caps;
    }

    fn equal(context: *anyopaque, first: []const u8, second: []const u8) p.ProviderError!bool {
        const self = owner(context);
        const result = try self.standard.provider().vtable.constantTimeEqual(context, first, second);
        if (self.armed and self.cancel_finished) {
            self.finished_checks += 1;
            self.parent.cancel();
        }
        return result;
    }
};

const Worker = struct {
    socket: *net.Socket,
    config: engine.ServerTLSConfig,
    observed: *Observed,
    context: *IoContext,
    allocator: std.mem.Allocator = testing.allocator,
    legacy: bool = false,
    exchange: bool = false,
    read_ms: u64 = 2_000,
    write_ms: u64 = 2_000,
    failure: ?anyerror = null,
    done: AtomicBool = .init(false),
    finished_ns: u64 = 0,
    handshakes: usize = 0,

    fn run(self: *@This()) void {
        self.observed.armed = true;
        self.serve() catch |err| {
            self.failure = err;
        };
        self.socket.shutdownWrite() catch {};
        self.finished_ns = context_mod.monotonicNowNs();
        self.done.store(true, .release);
    }

    fn serve(self: *@This()) !void {
        var connection = if (self.legacy)
            try engine.acceptServer(self.allocator, self.socket, &.{"http/1.1"}, self.config)
        else
            try engine.acceptServerWithIo(self.allocator, self.socket, &.{"http/1.1"}, self.config, .{
                .context = self.context,
                .read_timeout_ms = self.read_ms,
                .write_timeout_ms = self.write_ms,
            });
        defer connection.deinit();
        self.handshakes += 1;
        try testing.expectEqual(self.observed.version, connection.tlsVersion());
        try testing.expectEqualStrings("http/1.1", connection.negotiatedAlpn().?);
        try testing.expectEqual(self.config.crypto_provider.?.context, connection.crypto_provider.?.context);
        try testing.expectEqual(self.config.crypto_provider.?.vtable, connection.crypto_provider.?.vtable);
        if (!self.exchange) return error.FixtureUnexpectedHandshake;
        // Handshake options are not retained. Application calls explicitly
        // select a fresh context, even after cancelling the handshake context.
        self.context.cancel();
        var application = IoContext.init(.{ .request_deadline = Deadline.afterMs(2_000) });
        var request: [4]u8 = undefined;
        try readExact(&connection, &request, &application);
        try testing.expectEqualStrings("ping", &request);
        try connection.writeAllWithContext("pong", &application);
    }
};

fn serverConfig(chain: *const fixtures.Chain, provider: p.CryptoProvider) !engine.ServerTLSConfig {
    return engine.ServerTLSConfig.init(testing.allocator, testing.io, &.{ chain.leaf, chain.intermediate }, .{
        .algorithm = .ecdsa_p256,
        .encoding = .raw_secret,
        .bytes = &chain.leaf_key.ecdsa_p256.secret_key.toBytes(),
    }, provider);
}

fn readExact(connection: *engine.Connection, output: []u8, context: *const IoContext) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try connection.readWithContext(output[offset..], context);
        if (count == 0) return error.FixtureUnexpectedEof;
        offset += count;
    }
}

fn waitFor(flag: *const AtomicBool, timeout_ms: u64) !void {
    var bound = IoContext.init(.{ .request_deadline = Deadline.afterMs(timeout_ms) });
    while (!flag.load(.acquire)) try bound.waitForMs(1);
}

fn expectPending(worker: *const Worker) !void {
    var bound = IoContext.init(.{ .request_deadline = Deadline.afterMs(50) });
    while (true) {
        if (worker.done.load(.acquire)) return error.FixtureCompletedBeforeCancellation;
        bound.waitForMs(1) catch |err| return if (err == error.Timeout) {} else err;
    }
}

test "TLS server context pre-cancellation and expired parent precede all I/O" {
    var socket: net.Socket = undefined;
    var parent = IoContext.init(.{ .request_deadline = Deadline.at(0) });
    const options = engine.ServerHandshakeIoOptions{ .context = &parent, .read_timeout_ms = 2_000, .write_timeout_ms = 2_000 };
    try testing.expectError(error.Timeout, engine.acceptServerWithIo(testing.failing_allocator, &socket, &.{}, null, options));
    parent.cancel();
    try testing.expectError(error.Cancelled, engine.acceptServerWithIo(testing.failing_allocator, &socket, &.{}, null, options));
    var active = IoContext.init(.{});
    try testing.expectError(error.TlsInvalidPrivateKey, engine.acceptServerWithIo(testing.allocator, &socket, &.{}, null, .{ .context = &active }));
    try testing.expectError(error.TlsInvalidPrivateKey, engine.acceptServer(testing.allocator, &socket, &.{}, null));
}

fn preCancelledAncestor(expired: bool) !void {
    var socket: net.Socket = undefined;
    var external: @import("../core/types.zig").CancellationToken = .{};
    var ancestor = IoContext.init(.{ .request_deadline = if (expired) Deadline.at(0) else null });
    ancestor.cancel();
    const child = IoContext.init(.{ .parent = &ancestor, .external_cancel = &external });
    try testing.expectError(error.Cancelled, engine.acceptServerWithIo(testing.failing_allocator, &socket, &.{}, null, .{
        .context = &child,
        .read_timeout_ms = 2_000,
        .write_timeout_ms = 2_000,
    }));
    try testing.expect(!external.isCancelled());
    try testing.expect(!child.isLocallyCancelled());
}

test "TLS server context cancelled ancestor precedes configuration and I/O despite an uncancelled external token" {
    try preCancelledAncestor(false);
}

test "TLS server context cancelled ancestor beats an expired request deadline despite an uncancelled external token" {
    try preCancelledAncestor(true);
}

test "TLS server context cancels blocked initial and partial records within the shutdown bound" {
    var chain = try fixtures.Chain.init(testing.allocator, .ecdsa_p256);
    defer chain.deinit();
    const prefixes = [_][]const u8{ "", "\x16\x03", "\x16\x03\x03\x00\x09\x01\x00" };
    const Cancellation = enum { local, external, ancestor_local, ancestor_external };
    for (prefixes) |prefix| {
        for (std.enums.values(Cancellation)) |source| {
            var pair = try Pair.init();
            defer pair.deinit();
            var token: @import("../core/types.zig").CancellationToken = .{};
            var ancestor_token: @import("../core/types.zig").CancellationToken = .{};
            var ancestor = IoContext.init(.{ .external_cancel = &ancestor_token });
            const nested = source == .ancestor_local or source == .ancestor_external;
            var parent = IoContext.init(.{
                .external_cancel = if (source == .local) null else &token,
                .parent = if (nested) &ancestor else null,
            });
            var observed = Observed{ .standard = .init(testing.io, testing.allocator), .parent = &parent };
            var selected = observed.standard.provider();
            var vtable = selected.vtable.*;
            vtable.capabilities = Observed.capabilities;
            selected.vtable = &vtable;
            var config = try serverConfig(&chain, selected);
            defer config.deinit();
            if (prefix.len != 0) {
                try pair.peer.sendAll(prefix);
                try testing.expect(pair.accepted.waitReadable(2_000));
            }
            var worker = Worker{ .socket = &pair.accepted, .config = config, .observed = &observed, .context = &parent };
            const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
            var joined = false;
            defer if (!joined) {
                parent.cancel();
                pair.peer.close();
                thread.join();
            };
            try waitFor(&observed.entered, 2_000);
            if (prefix.len != 0) {
                var consumed = IoContext.init(.{ .request_deadline = Deadline.afterMs(2_000) });
                while (pair.accepted.waitReadable(0)) {
                    if (worker.done.load(.acquire)) return error.FixtureDidNotConsumePrefix;
                    try consumed.waitForMs(1);
                }
            }
            try expectPending(&worker);
            const start = context_mod.monotonicNowNs();
            switch (source) {
                .local => parent.cancel(),
                .external => token.cancel(),
                .ancestor_local => ancestor.cancel(),
                .ancestor_external => ancestor_token.cancel(),
            }
            // The two-second logical/socket budgets remain intact. The peer
            // stays open throughout cancellation; watchdog cleanup cannot pass.
            waitFor(&worker.done, 3_000) catch return error.FixtureCancellationWatchdog;
            thread.join();
            joined = true;
            const elapsed_us = (worker.finished_ns - start) / std.time.ns_per_us;
            errdefer std.debug.print("TLS server cancellation: prefix_len={d} source={s} elapsed_us={d}\n", .{ prefix.len, @tagName(source), elapsed_us });
            try testing.expectEqual(@as(?anyerror, error.Cancelled), worker.failure);
            try testing.expectEqual(@as(usize, 0), worker.handshakes);
            try testing.expect(elapsed_us < 1_000_000);
            try testing.expectEqual(source == .local, parent.isLocallyCancelled());
            try testing.expectEqual(source == .external, token.isCancelled());
            try testing.expectEqual(source == .ancestor_local, ancestor.isLocallyCancelled());
            try testing.expectEqual(source == .ancestor_external, ancestor_token.isCancelled());
        }
    }
}

test "TLS server context enforces explicit read budget and an earlier parent deadline" {
    var chain = try fixtures.Chain.init(testing.allocator, .ecdsa_p256);
    defer chain.deinit();
    const Source = enum { read_budget, parent_request, parent_phase };
    for (std.enums.values(Source)) |source| {
        var pair = try Pair.init();
        defer pair.deinit();
        var parent = IoContext.init(.{});
        var observed = Observed{ .standard = .init(testing.io, testing.allocator), .parent = &parent };
        var config = try serverConfig(&chain, observed.standard.provider());
        defer config.deinit();
        if (source == .parent_request) parent.request_deadline = Deadline.afterMs(80);
        if (source == .parent_phase) parent.phase_deadline = Deadline.afterMs(80);
        const original = parent.request_deadline;
        const original_phase = parent.phase_deadline;
        const start = context_mod.monotonicNowNs();
        try testing.expectError(error.Timeout, engine.acceptServerWithIo(testing.allocator, &pair.accepted, &.{"http/1.1"}, config, .{
            .context = &parent,
            .read_timeout_ms = if (source == .read_budget) 80 else 2_000,
            .write_timeout_ms = 2_000,
        }));
        const elapsed_ms = (context_mod.monotonicNowNs() - start) / std.time.ns_per_ms;
        try testing.expect(elapsed_ms >= 40 and elapsed_ms < 1_000);
        try testing.expectEqual(original, parent.request_deadline);
        try testing.expectEqual(original_phase, parent.phase_deadline);
    }
}

fn authenticated(version: Version, legacy: bool, fail_index: ?usize, cancel_finished: bool) !void {
    errdefer std.debug.print("TLS server context fixture: version={s} legacy={} allocation={?d} finished_cancel={}\n", .{ @tagName(version), legacy, fail_index, cancel_finished });
    var chain = try fixtures.Chain.init(testing.allocator, .ecdsa_p256);
    defer chain.deinit();
    var pair = try Pair.init();
    defer pair.deinit();
    var parent = IoContext.init(.{});
    if (legacy) parent.cancel();
    var observed = Observed{ .standard = .init(testing.io, testing.allocator), .parent = &parent, .version = version, .cancel_finished = cancel_finished };
    var selected = observed.standard.provider();
    var vtable = selected.vtable.*;
    vtable.capabilities = Observed.capabilities;
    vtable.constantTimeEqual = Observed.equal;
    selected.vtable = &vtable;
    var config = try serverConfig(&chain, selected);
    defer config.deinit();
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index orelse std.math.maxInt(usize) });
    var worker = Worker{
        .socket = &pair.accepted,
        .config = config,
        .observed = &observed,
        .context = &parent,
        .allocator = failing.allocator(),
        .legacy = legacy,
        .exchange = true,
    };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        parent.cancel();
        pair.peer.close();
        thread.join();
    };
    var client_observed = Observed{ .standard = .init(testing.io, testing.allocator), .version = version, .parent = &parent };
    var client_provider = client_observed.standard.provider();
    var client_vtable = client_provider.vtable.*;
    client_vtable.capabilities = Observed.capabilities;
    client_provider.vtable = &client_vtable;
    const client_config = engine.TLSConfig{
        .allocator = testing.allocator,
        .alpn_protocols = &.{"http/1.1"},
        .crypto_provider = client_provider,
        .server_authentication = .{ .verify = .{ .custom_only = .{ .der_certificates = &.{chain.root} } } },
    };
    var connection = engine.connectClient(testing.allocator, &pair.peer, &client_config, "127.0.0.1") catch |err| {
        if (fail_index == null and !cancel_finished) return err;
        try waitFor(&worker.done, 3_000);
        thread.join();
        joined = true;
        try testing.expectEqual(@as(?anyerror, if (fail_index != null) error.OutOfMemory else error.Cancelled), worker.failure);
        try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        return;
    };
    defer connection.deinit();
    try testing.expectEqual(version, connection.tlsVersion());
    if (fail_index == null and !cancel_finished) {
        var application = IoContext.init(.{ .request_deadline = Deadline.afterMs(2_000) });
        try connection.writeAllWithContext("ping", &application);
        var output: [4]u8 = undefined;
        try readExact(&connection, &output, &application);
        try testing.expectEqualStrings("pong", &output);
    }
    try waitFor(&worker.done, 3_000);
    thread.join();
    joined = true;
    try testing.expectEqual(@as(?anyerror, if (fail_index != null) error.OutOfMemory else if (cancel_finished) error.Cancelled else null), worker.failure);
    try testing.expectEqual(@as(usize, if (cancel_finished or fail_index != null) 0 else 1), worker.handshakes);
    if (cancel_finished) try testing.expectEqual(@as(usize, 1), observed.finished_checks);
    try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "TLS server context accepts TLS12 TLS13 and leaves legacy and post-handshake I/O explicit" {
    for ([_]Version{ .tls_1_2, .tls_1_3 }) |version| {
        try authenticated(version, false, null, false);
        try authenticated(version, true, null, false);
    }
}

test "TLS server context allocation failures and final cancellation release connection state" {
    for ([_]Version{ .tls_1_2, .tls_1_3 }) |version|
        for (0..3) |index| try authenticated(version, false, index, false);
    try authenticated(.tls_1_3, false, null, true);
}
