const std = @import("std");
const testing = std.testing;
const Client = @import("client.zig").Client;
const types = @import("../core/types.zig");
const net = @import("../net/socket.zig");
const engine = @import("../tls/tls.zig");
const trust = @import("../tls/trust.zig");
const crypto = @import("../tls/crypto/provider.zig");
const fixtures = @import("../tls/trust_fixtures.zig");
const platform = @import("../tls/platform_trust.zig");
const http = @import("../protocol/http.zig");
const streams = @import("../protocol/stream.zig");
const Version = std.crypto.tls.ProtocolVersion;

const Api = enum { connection, streaming_h1, streaming_h2 };
const Case = enum {
    matching,
    provider_context,
    provider_vtable,
    provider_missing,
    adapter_missing,
    adapter_mismatch,
    policy_disabled,
    backend_disabled,
    hash_failed,
    metadata_oom,
    signature_failed,
    fingerprint_denied,
    path_depth,
};

const Observed = struct {
    standard: engine.StandardCryptoProvider,
    version: Version,
    case: Case,
    bound_policy: trust.TrustProvider = undefined,
    in_policy: bool = false,
    policy_calls: usize = 0,
    verifier: ?trust.CertificateSignatureVerifier = null,
    request_time: i64 = 0,
    creates: usize = 0,
    updates: usize = 0,
    snapshots: usize = 0,
    destroys: usize = 0,
    signatures: usize = 0,
    seals: usize = 0,
    opens: usize = 0,

    fn owner(context: *anyopaque) *@This() {
        const implementation: *engine.StandardCryptoProvider = @ptrCast(@alignCast(context));
        return @fieldParentPtr("standard", implementation);
    }

    fn capabilities(context: *anyopaque) crypto.Capabilities {
        const self = owner(context);
        var result = self.standard.provider().vtable.capabilities(context);
        if (self.version == .tls_1_2) result.hkdf_hashes = 0;
        if (self.case == .backend_disabled) result.setHash(.sha1, false);
        return result;
    }

    fn verifyPeer(context: *anyopaque, request: trust.VerifyPeerRequest) trust.TrustError!void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.policy_calls += 1;
        self.verifier = request.signature_verifier;
        self.request_time = request.now_seconds;
        self.in_policy = true;
        defer self.in_policy = false;
        return self.bound_policy.verifyPeer(request);
    }

    fn hashCreate(context: *anyopaque, allocator: std.mem.Allocator, algorithm: crypto.HashAlgorithm, output: *?*anyopaque) crypto.ProviderError!void {
        const self = owner(context);
        if (self.in_policy) {
            self.creates += 1;
            if (self.case == .metadata_oom) {
                output.* = null;
                return error.OutOfMemory;
            }
        }
        return self.standard.provider().vtable.hashCreate(context, allocator, algorithm, output);
    }

    fn hashUpdate(context: *anyopaque, handle: *anyopaque, bytes: []const u8) crypto.ProviderError!void {
        const self = owner(context);
        if (self.in_policy) {
            self.updates += 1;
            if (self.case == .hash_failed) return error.InternalError;
        }
        return self.standard.provider().vtable.hashUpdate(context, handle, bytes);
    }

    fn hashSnapshot(context: *anyopaque, handle: *anyopaque, output: []u8) crypto.ProviderError!void {
        const self = owner(context);
        if (self.in_policy) self.snapshots += 1;
        return self.standard.provider().vtable.hashSnapshot(context, handle, output);
    }

    fn hashDestroy(context: *anyopaque, allocator: std.mem.Allocator, handle: *anyopaque) void {
        const self = owner(context);
        if (self.in_policy) self.destroys += 1;
        self.standard.provider().vtable.hashDestroy(context, allocator, handle);
    }

    fn verify(context: *anyopaque, scheme: crypto.SignatureScheme, key: crypto.PublicKey, parts: []const []const u8, signature: []const u8) crypto.ProviderError!void {
        const self = owner(context);
        if (self.in_policy) {
            self.signatures += 1;
            if (self.case == .signature_failed) return error.SignatureInvalid;
        }
        return self.standard.provider().vtable.verify(context, scheme, key, parts, signature);
    }

    fn seal(context: *anyopaque, algorithm: crypto.AeadAlgorithm, key: []const u8, nonce: []const u8, aad: []const []const u8, plain: []const u8, encrypted: []u8, tag: []u8) crypto.ProviderError!void {
        const self = owner(context);
        self.seals += 1;
        return self.standard.provider().vtable.aeadSeal(context, algorithm, key, nonce, aad, plain, encrypted, tag);
    }

    fn open(context: *anyopaque, algorithm: crypto.AeadAlgorithm, key: []const u8, nonce: []const u8, aad: []const []const u8, encrypted: []const u8, tag: []const u8, plain: []u8) crypto.ProviderError!void {
        const self = owner(context);
        self.opens += 1;
        return self.standard.provider().vtable.aeadOpen(context, algorithm, key, nonce, aad, encrypted, tag, plain);
    }
};

fn readExact(connection: *engine.Connection, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try connection.read(output[offset..]);
        if (count == 0) return error.UnexpectedEndOfStream;
        offset += count;
    }
}

fn writeFrame(connection: *engine.Connection, frame_type: http.HTTP2FrameType, flags: u8, stream_id: u31, payload: []const u8) !void {
    const header = (http.HTTP2FrameHeader{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    }).serialize();
    try connection.writeAll(&header);
    try connection.writeAll(payload);
}

const Peer = struct {
    listener: *net.TcpListener,
    config: engine.ServerTLSConfig,
    api: Api,
    version: Version,
    handshakes: usize = 0,
    requests: usize = 0,
    failure: ?anyerror = null,
    client_done: std.atomic.Value(bool) = .init(false),

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            self.failure = err;
        };
    }

    fn serve(self: *@This()) !void {
        if (!self.listener.socket.waitReadable(2_000)) return error.FixtureAcceptTimeout;
        var accepted = try self.listener.accept();
        defer accepted.socket.close();
        try accepted.socket.setRecvTimeout(2_000);
        try accepted.socket.setSendTimeout(2_000);
        const protocols: []const []const u8 = if (self.api == .streaming_h2) &.{"h2"} else &.{"http/1.1"};
        var connection = try engine.acceptServer(testing.allocator, &accepted.socket, protocols, self.config);
        defer connection.deinit();
        self.handshakes += 1;
        try testing.expectEqual(self.version, connection.tlsVersion());
        try testing.expectEqualStrings(protocols[0], connection.negotiatedAlpn().?);

        if (self.api == .streaming_h2) return self.serveH2(&connection);
        while (self.requests < 2) {
            if (self.api == .connection) {
                var request: [4]u8 = undefined;
                try readExact(&connection, &request);
                try testing.expectEqualStrings("ping", &request);
                try connection.writeAll("pong");
            } else {
                var request: [4096]u8 = undefined;
                var length: usize = 0;
                while (std.mem.indexOf(u8, request[0..length], "\r\n\r\n") == null) {
                    if (length == request.len) return error.FixtureRequestTooLarge;
                    const count = try connection.read(request[length..]);
                    if (count == 0) return error.UnexpectedEndOfStream;
                    length += count;
                }
                try connection.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nbound");
            }
            self.requests += 1;
        }
    }

    fn serveH2(self: *@This(), connection: *engine.Connection) !void {
        var preface: [http.HTTP2_PREFACE.len]u8 = undefined;
        try readExact(connection, &preface);
        try testing.expectEqualStrings(http.HTTP2_PREFACE, &preface);
        try writeFrame(connection, .settings, 0, 0, "");
        var manager = streams.StreamManager.init(testing.allocator, false);
        defer manager.deinit();
        var payload: [16_384]u8 = undefined;
        var last_stream: u31 = 0;
        var current_stream: u31 = 0;
        // Finish still sends flow-control frames; keep the peer alive until pool teardown.
        for (0..128) |_| {
            var bytes: [9]u8 = undefined;
            const count = connection.read(&bytes) catch |err| {
                if (err == error.TlsConnectionTruncated and self.requests == 2 and self.client_done.load(.acquire)) return;
                return err;
            };
            if (count == 0) {
                if (self.requests == 2 and self.client_done.load(.acquire)) return;
                return error.UnexpectedEndOfStream;
            }
            try readExact(connection, bytes[count..]);
            const header = http.HTTP2FrameHeader.parse(bytes);
            if (header.length > payload.len) return error.FixtureFrameTooLarge;
            try readExact(connection, payload[0..header.length]);
            switch (header.frame_type) {
                .settings => {
                    if (header.flags & 1 == 0) try writeFrame(connection, .settings, 1, 0, "");
                },
                .window_update => {},
                .headers => {
                    if (self.requests == 2) return error.FixtureUnexpectedFrame;
                    try testing.expect(header.stream_id > last_stream);
                    try testing.expect(header.flags & 4 != 0);
                    current_stream = header.stream_id;
                    if (header.flags & 1 == 0) continue;
                },
                .data => {
                    if (self.requests == 2) return error.FixtureUnexpectedFrame;
                    try testing.expectEqual(current_stream, header.stream_id);
                    if (header.flags & 1 == 0) continue;
                },
                else => return error.FixtureUnexpectedFrame,
            }
            if (header.frame_type != .headers and header.frame_type != .data) continue;
            const headers = try streams.buildHeadersAndContinuations(&manager, current_stream, &.{
                .{ .name = ":status", .value = "200", .representation = .without_indexing },
                .{ .name = "content-length", .value = "5", .representation = .without_indexing },
            }, null, 16_384, false, testing.allocator);
            defer testing.allocator.free(headers);
            try connection.writeAll(headers);
            try writeFrame(connection, .data, 1, current_stream, "bound");
            last_stream = current_stream;
            self.requests += 1;
        }
        return error.FixtureFrameLimit;
    }
};

fn drive(client: *Client, address: @import("../net/compat.zig").Address, api: Api) !void {
    if (api == .connection) {
        var socket = try net.Socket.create();
        defer socket.close();
        try socket.connectWithTimeout(address, 2_000);
        try socket.setRecvTimeout(2_000);
        try socket.setSendTimeout(2_000);
        const config = client.makeTlsConfig(true, &.{"http/1.1"});
        var connection = try engine.connectClient(testing.allocator, &socket, &config, "127.0.0.1");
        defer connection.deinit();
        try testing.expectEqual(config.crypto_provider.?.context, connection.crypto_provider.?.context);
        try testing.expectEqual(config.crypto_provider.?.vtable, connection.crypto_provider.?.vtable);
        for (0..2) |_| {
            try connection.writeAll("ping");
            var response: [4]u8 = undefined;
            try readExact(&connection, &response);
            try testing.expectEqualStrings("pong", &response);
        }
        return;
    }
    var url_buffer: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buffer, "https://127.0.0.1:{d}/paired", .{address.getPort()});
    for (0..2) |_| {
        var operation = try client.open(.GET, url, .{
            .version = if (api == .streaming_h2) .HTTP_2 else .HTTP_1_1,
        });
        defer operation.deinit();
        const head = try operation.finishRequest(null);
        try testing.expectEqual(@as(u16, 200), head.status.code);
        try testing.expectEqual(if (api == .streaming_h2) types.Version.HTTP_2 else .HTTP_1_1, head.version);
        var response: [5]u8 = undefined;
        var offset: usize = 0;
        while (offset < response.len) {
            const count = try operation.read(response[offset..]);
            if (count == 0) return error.UnexpectedEndOfStream;
            offset += count;
        }
        try testing.expectEqualStrings("bound", &response);
        var extra: [1]u8 = undefined;
        try testing.expectEqual(@as(usize, 0), try operation.read(&extra));
        try operation.finish(.{});
        try testing.expectEqual(@as(usize, 0), client.poolStats().active);
        try testing.expectEqual(@as(usize, 1), client.poolStats().idle);
    }
}

fn exercise(api: Api, version: Version, case: Case) !void {
    errdefer std.debug.print("TLS canonical pairing: api={s} version={s} case={s}\n", .{ @tagName(api), @tagName(version), @tagName(case) });
    var chain = try fixtures.Chain.init(testing.allocator, .ecdsa_p256);
    defer chain.deinit();
    var roots = try engine.TrustContext.init(testing.allocator, testing.io, .{
        .source = .{ .custom_only = .{ .der_certificates = &.{chain.root} } },
        .load_time_seconds = 1_700_000_000,
    });
    defer roots.deinit();
    roots.platform_snapshot = platform.Snapshot.init(testing.allocator, .{});
    var identifier: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(chain.leaf, &identifier, .{});
    const entry = try platform.FingerprintEntry.init(.sha1, &identifier, .{
        .roles = if (case == .fingerprint_denied) 0 else 3,
    });
    try roots.platform_snapshot.?.addFingerprintList(.{
        .algorithm = .sha1,
        .this_update = 1_700_000_000,
        .next_update = 2_524_608_000,
        .entries = &.{entry},
    });
    var observed: Observed = .{
        .standard = .init(testing.io, testing.allocator),
        .version = version,
        .case = case,
    };
    var selected = observed.standard.provider();
    var vtable = selected.vtable.*;
    vtable.capabilities = Observed.capabilities;
    vtable.hashCreate = Observed.hashCreate;
    vtable.hashUpdate = Observed.hashUpdate;
    vtable.hashSnapshot = Observed.hashSnapshot;
    vtable.hashDestroy = Observed.hashDestroy;
    vtable.verify = Observed.verify;
    vtable.aeadSeal = Observed.seal;
    vtable.aeadOpen = Observed.open;
    selected.vtable = &vtable;
    var adapter = engine.CryptoCertificateVerifier.init(selected);
    var other_adapter = engine.CryptoCertificateVerifier.init(selected);
    var binding = try roots.bind(&adapter, .{ .allow_sha1_identifiers = case != .policy_disabled });
    observed.bound_policy = binding.provider();
    var alternate: Observed = .{ .standard = .init(testing.io, testing.allocator), .version = version, .case = case };
    var copied_vtable = vtable;
    var configured = selected;
    if (case == .provider_context) configured.context = alternate.standard.provider().context;
    if (case == .provider_vtable) configured.vtable = &copied_vtable;
    if (case == .provider_context or case == .provider_vtable) {
        try testing.expectEqualDeep(selected.vtable.capabilities(selected.context), configured.vtable.capabilities(configured.context));
        try testing.expectEqual(selected.abi_version, configured.abi_version);
        try testing.expectEqual(case == .provider_vtable, selected.context == configured.context);
        try testing.expectEqual(case == .provider_context, selected.vtable == configured.vtable);
    }
    var server_config = try engine.ServerTLSConfig.init(testing.allocator, testing.io, &.{ chain.leaf, chain.intermediate }, .{
        .algorithm = .ecdsa_p256,
        .encoding = .raw_secret,
        .bytes = &chain.leaf_key.ecdsa_p256.secret_key.toBytes(),
    }, null);
    defer server_config.deinit();
    var listener = try net.TcpListener.init(try @import("../net/compat.zig").Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const address = try listener.getLocalAddress();
    var client = try Client.tryInitWithConfig(testing.allocator, .{
        .tls_crypto_provider = if (case == .provider_missing) null else configured,
        .tls_certificate_crypto = if (case == .adapter_missing) null else if (case == .adapter_mismatch) &other_adapter else &adapter,
        .server_authentication = .{ .verify = .{ .provider = .{
            .context = &observed,
            .vtable = &.{ .verify_peer = Observed.verifyPeer },
        } } },
        .tls_trust_limits = if (case == .path_depth) .{ .max_path_depth = 2 } else .{},
        .http2_enabled = api == .streaming_h2,
        .policy = types.ClientPolicy.embeddingOwned(),
        .timeouts = types.Timeouts.uniform(2_000),
    });
    var client_alive = true;
    defer if (client_alive) client.deinit();
    if (case != .adapter_missing and case != .adapter_mismatch) {
        const verifier = client.configuration().tls_certificate_crypto.?.verifier();
        try testing.expectEqual(binding.signatureVerifier().context, verifier.context);
        try testing.expectEqual(binding.signatureVerifier().vtable, verifier.vtable);
    }
    var peer: Peer = .{ .listener = &listener, .config = server_config, .api = api, .version = version };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    errdefer std.debug.print("TLS canonical peer: handshakes={d} requests={d} failure={s}\n", .{
        peer.handshakes,
        peer.requests,
        if (peer.failure) |err| @errorName(err) else "none",
    });
    defer if (!joined) {
        peer.client_done.store(true, .release);
        client.deinit();
        client_alive = false;
        thread.join();
    };
    const result = drive(&client, address, api);
    if (case == .matching) {
        try result;
    } else {
        const expected = switch (case) {
            .matching => unreachable,
            .provider_context, .provider_vtable, .provider_missing, .adapter_missing, .adapter_mismatch => error.TlsInvalidTrustConfiguration,
            .policy_disabled, .backend_disabled, .hash_failed => error.TlsTrustStoreLoadFailed,
            .metadata_oom => error.OutOfMemory,
            .signature_failed => error.TlsCertificateSignatureInvalid,
            .fingerprint_denied => error.TlsCertificateConstraintViolation,
            .path_depth => error.TlsCertificatePathTooDeep,
        };
        try testing.expectError(expected, result);
    }
    try testing.expectEqual(@as(usize, 0), client.poolStats().active);
    try testing.expectEqual(@as(usize, 0), client.shared.in_flight.load(.acquire));
    if (case != .matching) try testing.expectEqual(@as(usize, 0), client.poolStats().idle);
    peer.client_done.store(true, .release);
    client.deinit();
    client_alive = false;
    thread.join();
    joined = true;
    if (case == .metadata_oom) {
        try testing.expectEqual(@as(usize, 1), observed.creates);
        try testing.expectEqual(@as(usize, 0), observed.destroys);
    } else {
        try testing.expectEqual(observed.creates, observed.destroys);
    }
    if (case == .matching) {
        if (peer.failure) |err| return err;
        try testing.expectEqual(@as(usize, 1), peer.handshakes);
        try testing.expectEqual(@as(usize, 2), peer.requests);
        try testing.expectEqual(@as(usize, 1), observed.policy_calls);
        try testing.expectEqual(binding.signatureVerifier().context, observed.verifier.?.context);
        try testing.expectEqual(binding.signatureVerifier().vtable, observed.verifier.?.vtable);
        try testing.expect(observed.request_time > 1_700_000_000);
        try testing.expect(observed.creates >= 3);
        try testing.expectEqual(observed.creates, observed.updates);
        try testing.expectEqual(observed.creates, observed.snapshots);
        try testing.expect(observed.signatures >= 2);
        try testing.expect(observed.seals > 0 and observed.opens > 0);
    } else {
        try testing.expect(peer.failure != null);
        try testing.expectEqual(@as(usize, 0), peer.handshakes);
        try testing.expectEqual(@as(usize, 0), peer.requests);
        switch (case) {
            .provider_context, .provider_vtable, .provider_missing => {
                try testing.expectEqual(@as(usize, 0), observed.policy_calls);
                try testing.expectEqual(@as(usize, 0), observed.creates);
                try testing.expectEqual(@as(usize, 0), observed.signatures);
            },
            .adapter_missing, .adapter_mismatch, .policy_disabled, .backend_disabled => {
                try testing.expectEqual(@as(usize, 0), observed.creates);
                try testing.expectEqual(@as(usize, 0), observed.signatures);
            },
            .hash_failed, .metadata_oom, .fingerprint_denied, .path_depth => {
                try testing.expectEqual(@as(usize, 1), observed.creates);
                try testing.expectEqual(@as(usize, 0), observed.signatures);
            },
            .signature_failed => try testing.expect(observed.signatures > 0),
            .matching => unreachable,
        }
    }
}

test "TLS canonical binding retains selected providers through public connections and streaming leases" {
    for ([_]Version{ .tls_1_2, .tls_1_3 }) |version| {
        for (std.enums.values(Api)) |api| {
            for (std.enums.values(Case)) |case| try exercise(api, version, case);
        }
    }
}
