const std = @import("std");
const testing = std.testing;
const Client = @import("client.zig").Client;
const types = @import("../core/types.zig");
const net = @import("../net/socket.zig");
const engine = @import("../tls/tls.zig");
const crypto = @import("../tls/crypto/provider.zig");
const fixtures = @import("../tls/trust_fixtures.zig");
const http = @import("../protocol/http.zig");
const Version = std.crypto.tls.ProtocolVersion;

const Ending = enum { close_notify, abrupt, truncated_record, partial_handshake, bad_mac, fatal_alert, user_canceled, fatal_close, invalid_close, cancel, provider_failure };
const H2 = enum { none, header, payload };
const Case = struct {
    name: []const u8,
    response: []const u8 = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc",
    body: []const u8 = "abc",
    ending: Ending = .close_notify,
    expected_error: ?anyerror = null,
    header_error: bool = false,
    trailers: bool = false,
    h2: H2 = .none,
    raw: bool = false,
};

const Observed = struct {
    standard: engine.StandardCryptoProvider,
    version: Version,
    ending: Ending,
    token: *types.CancellationToken,
    armed: bool = false,
    close_opens: usize = 0,

    fn owner(context: *anyopaque) *@This() {
        const implementation: *engine.StandardCryptoProvider = @ptrCast(@alignCast(context));
        return @fieldParentPtr("standard", implementation);
    }

    fn capabilities(context: *anyopaque) crypto.Capabilities {
        const self = owner(context);
        var result = self.standard.provider().vtable.capabilities(context);
        if (self.version == .tls_1_2) result.hkdf_hashes = 0;
        return result;
    }

    fn open(context: *anyopaque, algorithm: crypto.AeadAlgorithm, key: []const u8, nonce: []const u8, aad: []const []const u8, encrypted: []const u8, tag: []const u8, plain: []u8) crypto.ProviderError!void {
        const self = owner(context);
        if (self.armed) {
            self.close_opens += 1;
            if (self.ending == .cancel) self.token.cancel();
            if (self.ending == .provider_failure) return error.InternalError;
        }
        return self.standard.provider().vtable.aeadOpen(context, algorithm, key, nonce, aad, encrypted, tag, plain);
    }
};

fn readExact(connection: *engine.Connection, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const n = try connection.read(output[offset..]);
        if (n == 0) return error.FixtureUnexpectedEof;
        offset += n;
    }
}

const Peer = struct {
    listener: *net.TcpListener,
    config: engine.ServerTLSConfig,
    version: Version,
    case: Case,
    failure: ?anyerror = null,
    handshakes: usize = 0,

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
        const protocols: []const []const u8 = if (self.case.h2 != .none) &.{"h2"} else &.{"http/1.1"};
        var connection = try engine.acceptServer(testing.allocator, &accepted.socket, protocols, self.config);
        defer connection.deinit();
        self.handshakes += 1;
        try testing.expectEqual(self.version, connection.tlsVersion());
        try testing.expectEqualStrings(protocols[0], connection.negotiatedAlpn().?);
        if (self.case.h2 != .none) {
            try self.h2Response(&connection);
        } else {
            var request: [4096]u8 = undefined;
            var length: usize = 0;
            while (std.mem.indexOf(u8, request[0..length], "\r\n\r\n") == null) {
                if (length == request.len) return error.FixtureRequestTooLarge;
                const n = try connection.read(request[length..]);
                if (n == 0) return error.FixtureUnexpectedEof;
                length += n;
            }
            try connection.writeAll(self.case.response);
        }
        switch (self.case.ending) {
            .abrupt => {},
            .truncated_record => try accepted.socket.sendAll(&.{ 23, 3, 3, 0, 17, 0 }),
            else => {
                const alert: [2]u8 = switch (self.case.ending) {
                    .fatal_alert => .{ 2, @intFromEnum(std.crypto.tls.Alert.Description.internal_error) },
                    .user_canceled => .{ 1, @intFromEnum(std.crypto.tls.Alert.Description.user_canceled) },
                    .fatal_close => .{ 2, 0 },
                    .invalid_close => .{ 0, 0 },
                    else => .{ 1, 0 },
                };
                if (self.case.ending == .partial_handshake) try connection.writeEncryptedRecord("\x18\x00", .handshake);
                if (self.case.ending == .bad_mac) connection.app_write_key.?[0] ^= 1;
                try connection.writeEncryptedRecord(&alert, .alert);
            },
        }
        try accepted.socket.shutdownWrite();
    }

    fn h2Response(self: *@This(), connection: *engine.Connection) !void {
        var preface: [http.HTTP2_PREFACE.len]u8 = undefined;
        try readExact(connection, &preface);
        try testing.expectEqualStrings(http.HTTP2_PREFACE, &preface);
        const settings = (http.HTTP2FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 }).serialize();
        try connection.writeAll(&settings);
        var request_stream: ?u31 = null;
        for (0..16) |_| {
            var raw: [9]u8 = undefined;
            try readExact(connection, &raw);
            const header = http.HTTP2FrameHeader.parse(raw);
            var payload: [4096]u8 = undefined;
            if (header.length > payload.len) return error.FixtureFrameTooLarge;
            try readExact(connection, payload[0..header.length]);
            switch (header.frame_type) {
                .settings => {
                    if (header.flags & 1 == 0) {
                        const ack = (http.HTTP2FrameHeader{ .length = 0, .frame_type = .settings, .flags = 1, .stream_id = 0 }).serialize();
                        try connection.writeAll(&ack);
                    }
                    continue;
                },
                .window_update => continue,
                .headers => {
                    if (request_stream != null) return error.FixtureUnexpectedFrame;
                    request_stream = header.stream_id;
                    try testing.expect(header.flags & 4 != 0);
                },
                .data => try testing.expectEqual(request_stream orelse return error.FixtureUnexpectedFrame, header.stream_id),
                else => return error.FixtureUnexpectedFrame,
            }
            if (header.flags & 1 == 0) continue;
            const response = (http.HTTP2FrameHeader{ .length = 3, .frame_type = .headers, .flags = 4, .stream_id = header.stream_id }).serialize();
            if (self.case.h2 == .header) {
                try connection.writeAll(response[0..5]);
            } else {
                try connection.writeAll(&response);
                try connection.writeAll("\x88");
            }
            return;
        }
        return error.FixtureMissingRequest;
    }
};

fn exercise(version: Version, case: Case) !void {
    errdefer std.debug.print("HTTP TLS EOF fixture: version={s} case={s}\n", .{ @tagName(version), case.name });
    var chain = try fixtures.Chain.init(testing.allocator, .ecdsa_p256);
    defer chain.deinit();
    var token: types.CancellationToken = .{};
    var observed = Observed{ .standard = .init(testing.io, testing.allocator), .version = version, .ending = case.ending, .token = &token };
    var selected = observed.standard.provider();
    var vtable = selected.vtable.*;
    vtable.capabilities = Observed.capabilities;
    vtable.aeadOpen = Observed.open;
    selected.vtable = &vtable;
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
        .tls_crypto_provider = selected,
        .server_authentication = .{ .verify = .{ .custom_only = .{ .der_certificates = &.{chain.root} } } },
        .http2_enabled = case.h2 != .none,
        .policy = types.ClientPolicy.embeddingOwned(),
        .timeouts = types.Timeouts.uniform(2_000),
    });
    var client_alive = true;
    defer if (client_alive) client.deinit();
    var peer = Peer{ .listener = &listener, .config = server_config, .version = version, .case = case };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        client.deinit();
        client_alive = false;
        thread.join();
    };

    if (case.raw) {
        var socket = try net.Socket.create();
        defer socket.close();
        try socket.connectWithTimeout(address, 2_000);
        try socket.setRecvTimeout(2_000);
        try socket.setSendTimeout(2_000);
        const config = client.makeTlsConfig(true, &.{"http/1.1"});
        var connection = try engine.connectClient(testing.allocator, &socket, &config, "127.0.0.1");
        defer connection.deinit();
        try connection.writeAll("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        thread.join();
        joined = true;
        if (peer.failure) |err| {
            std.debug.print("HTTP TLS EOF peer failure: {s}\n", .{@errorName(err)});
            return err;
        }
        var byte: [1]u8 = undefined;
        try testing.expectError(case.expected_error.?, connection.read(&byte));
        return;
    }

    var url_buffer: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buffer, "https://127.0.0.1:{d}/eof", .{address.getPort()});
    var operation = try client.open(.GET, url, .{
        .version = if (case.h2 != .none) .HTTP_2 else .HTTP_1_1,
        .cancel_token = &token,
    });
    defer operation.deinit();
    var head_failure: ?anyerror = null;
    _ = operation.finishRequest(null) catch |err| blk: {
        head_failure = err;
        break :blk null;
    };
    thread.join();
    joined = true;
    if (peer.failure) |err| return err;
    try testing.expectEqual(@as(usize, 1), peer.handshakes);
    if (case.header_error) {
        try testing.expectEqual(case.expected_error, head_failure);
        try testing.expectError(case.expected_error.?, operation.finish(.{}));
    } else {
        if (head_failure) |err| return err;
        observed.armed = true;
        var bytes: [64]u8 = undefined;
        var length: usize = 0;
        var body_failure: ?anyerror = null;
        while (true) {
            if (length == bytes.len) return error.FixtureBodyTooLarge;
            const n = operation.read(bytes[length..][0..@min(2, bytes.len - length)]) catch |err| {
                body_failure = err;
                break;
            };
            if (n == 0) break;
            length += n;
        }
        try testing.expectEqualStrings(case.body, bytes[0..length]);
        try testing.expectEqual(case.expected_error, body_failure);
        if (case.expected_error) |expected| {
            try testing.expectError(expected, operation.read(bytes[0..1]));
            try testing.expectError(expected, operation.finish(.{}));
        } else {
            if (case.trailers) try testing.expectEqualStrings("yes", operation.trailers().?.get("X-End").?);
            try operation.finish(.{});
        }
        if (case.ending == .cancel or case.ending == .provider_failure) try testing.expectEqual(@as(usize, 1), observed.close_opens);
    }
    operation.abort();
    try testing.expectEqual(@as(usize, 0), client.poolStats().active);
    try testing.expectEqual(@as(usize, 0), client.poolStats().idle);
}

test "TLS authenticated EOF lets HTTP1 framing decide completion or truncation" {
    const cases = [_]Case{
        .{ .name = "fixed complete", .response = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc" },
        .{ .name = "fixed short", .response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabc", .expected_error = error.ResponseBodyUnderrun },
        .{ .name = "fixed short without close header", .response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc", .expected_error = error.ResponseBodyUnderrun },
        .{ .name = "chunked complete", .response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n", .trailers = true },
        .{ .name = "chunked short", .response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nabc", .expected_error = error.MalformedChunk },
        .{ .name = "chunk CRLF missing", .response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc", .expected_error = error.MalformedChunk },
        .{ .name = "trailer truncated", .response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\nX-End: yes\r\n", .expected_error = error.MalformedChunk },
        .{ .name = "close delimited complete" },
        .{ .name = "close delimited without close header", .response = "HTTP/1.1 200 OK\r\n\r\nabc" },
        .{ .name = "close delimited empty", .response = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", .body = "" },
        .{ .name = "header EOF", .response = "HTTP/1.1 200 OK\r\nContent-Length:", .body = "", .header_error = true, .expected_error = error.UnexpectedEof },
    };
    for ([_]Version{ .tls_1_2, .tls_1_3 }) |version| for (cases) |case| try exercise(version, case);
}

test "TLS HTTP EOF conversion preserves other alerts authentication failures and cancellation" {
    const cases = [_]Case{
        .{ .name = "no authenticated close", .ending = .abrupt, .expected_error = error.TlsConnectionTruncated },
        .{ .name = "partial TLS record", .ending = .truncated_record, .expected_error = error.TlsConnectionTruncated },
        .{ .name = "invalid authentication tag", .ending = .bad_mac, .expected_error = error.TlsDecryptError },
        .{ .name = "fatal alert", .ending = .fatal_alert, .expected_error = error.TlsInternalError },
        .{ .name = "user canceled is not EOF", .ending = .user_canceled, .expected_error = error.TlsCloseNotify },
        .{ .name = "fatal close is not EOF", .ending = .fatal_close, .expected_error = error.TlsCloseNotify },
        .{ .name = "invalid close level is not EOF", .ending = .invalid_close, .expected_error = error.TlsCloseNotify },
        .{ .name = "context cancellation wins", .ending = .cancel, .expected_error = error.Cancelled },
        .{ .name = "selected provider refusal", .ending = .provider_failure, .expected_error = error.InternalError },
    };
    for ([_]Version{ .tls_1_2, .tls_1_3 }) |version| for (cases) |case| try exercise(version, case);
    try exercise(.tls_1_3, .{ .name = "incomplete post-handshake message is not EOF", .ending = .partial_handshake, .expected_error = error.TlsCloseNotify });
}

test "TLS authenticated EOF during HTTP2 frame headers and payloads remains truncation" {
    for ([_]Version{ .tls_1_2, .tls_1_3 }) |version| {
        try exercise(version, .{ .name = "H2 frame header EOF", .h2 = .header, .header_error = true, .expected_error = error.UnexpectedEof });
        try exercise(version, .{ .name = "H2 frame payload EOF", .h2 = .payload, .header_error = true, .expected_error = error.UnexpectedEof });
    }
}

test "TLS public connection retains raw close_notify and alert semantics" {
    for ([_]Version{ .tls_1_2, .tls_1_3 }) |version| {
        for ([_]Ending{ .close_notify, .user_canceled, .fatal_close }) |ending| {
            try exercise(version, .{ .name = "raw alert", .response = "", .ending = ending, .expected_error = error.TlsCloseNotify, .raw = true });
        }
    }
}
