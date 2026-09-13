const std = @import("std");
const testing = std.testing;
const engine = @import("tls.zig");
const net = @import("../net/socket.zig");
const p = @import("crypto/provider.zig");
const record = @import("crypto/record.zig");
const tls = std.crypto.tls;
const Standard = @import("crypto/standard.zig").StandardProvider;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const IoContext = @import("../io/context.zig").IoContext;
const Deadline = @import("../io/context.zig").Deadline;

fn element(allocator: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]const u8 {
    const body = try std.mem.concat(allocator, u8, parts);
    var bytes: std.ArrayList(u8) = .empty;
    try bytes.append(allocator, tag);
    if (body.len < 128) {
        try bytes.append(allocator, @intCast(body.len));
    } else if (body.len < 256) {
        try bytes.appendSlice(allocator, &.{ 0x81, @intCast(body.len) });
    } else {
        if (body.len > 65535) return error.FixtureTooLarge;
        try bytes.appendSlice(allocator, &.{ 0x82, @intCast(body.len >> 8), @truncate(body.len) });
    }
    try bytes.appendSlice(allocator, body);
    return bytes.toOwnedSlice(allocator);
}

fn name(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    return element(allocator, 0x30, &.{try element(allocator, 0x31, &.{
        try element(allocator, 0x30, &.{ "\x06\x03\x55\x04\x03", try element(allocator, 0x0c, &.{value}) }),
    })});
}

fn extension(allocator: std.mem.Allocator, oid: []const u8, critical: bool, value: []const u8) ![]const u8 {
    return element(allocator, 0x30, &.{
        try element(allocator, 6, &.{oid}),
        if (critical) "\x01\x01\xff" else "",
        try element(allocator, 4, &.{value}),
    });
}

fn certificate(allocator: std.mem.Allocator, key: Ecdsa.KeyPair, issuer: Ecdsa.KeyPair, ca: bool) ![]const u8 {
    const algorithm = "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";
    const spki = try std.mem.concat(allocator, u8, &.{
        "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00",
        &key.public_key.toUncompressedSec1(),
    });
    const extensions = try element(allocator, 0x30, &.{
        try extension(allocator, "\x55\x1d\x13", true, if (ca) "\x30\x03\x01\x01\xff" else "\x30\x00"),
        try extension(allocator, "\x55\x1d\x0f", true, if (ca) "\x03\x02\x02\x04" else "\x03\x02\x07\x80"),
        if (ca) "" else try extension(allocator, "\x55\x1d\x25", false, "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01"),
        if (ca) "" else try extension(allocator, "\x55\x1d\x11", false, "\x30\x0b\x82\x09localhost"),
    });
    const validity = try element(allocator, 0x30, &.{
        "\x17\x0d240101000000Z", "\x17\x0d491231235959Z",
    });
    const tbs = try element(allocator, 0x30, &.{
        "\xa0\x03\x02\x01\x02",
        &.{ 2, 1, if (ca) 1 else 2 },
        algorithm,
        try name(allocator, "Test Root"),
        validity,
        try name(allocator, if (ca) "Test Root" else "localhost"),
        spki,
        try element(allocator, 0xa3, &.{extensions}),
    });
    const signed = try issuer.sign(tbs, null);
    var signature: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    return element(allocator, 0x30, &.{ tbs, algorithm, try element(allocator, 3, &.{ "\x00", signed.toDer(&signature) }) });
}

const Scenario = enum { round_trip, seal_denied, open_denied, capability_denied, key_update_denied };

const Observed = struct {
    standard: Standard,
    version: tls.ProtocolVersion,
    denial: ?Scenario = null,
    seals: usize = 0,
    opens: usize = 0,
    expansions: usize = 0,

    fn owner(context: *anyopaque) *@This() {
        const implementation: *Standard = @ptrCast(@alignCast(context));
        return @fieldParentPtr("standard", implementation);
    }

    fn capabilities(context: *anyopaque) p.Capabilities {
        const self = owner(context);
        var result = self.standard.provider().vtable.capabilities(context);
        result.aeads = 0;
        if (self.denial != .capability_denied) result.setAead(.aes_128_gcm, true);
        if (self.version == .tls_1_2) result.hkdf_hashes = 0;
        return result;
    }

    fn seal(context: *anyopaque, algorithm: p.AeadAlgorithm, key: []const u8, nonce: []const u8, aad: []const []const u8, plain: []const u8, encrypted: []u8, tag: []u8) p.ProviderError!void {
        const self = owner(context);
        self.seals += 1;
        if (self.denial == .seal_denied) return error.UnsupportedOperation;
        return self.standard.provider().vtable.aeadSeal(context, algorithm, key, nonce, aad, plain, encrypted, tag);
    }

    fn open(context: *anyopaque, algorithm: p.AeadAlgorithm, key: []const u8, nonce: []const u8, aad: []const []const u8, encrypted: []const u8, tag: []const u8, plain: []u8) p.ProviderError!void {
        const self = owner(context);
        self.opens += 1;
        if (self.denial == .open_denied) return error.UnsupportedOperation;
        return self.standard.provider().vtable.aeadOpen(context, algorithm, key, nonce, aad, encrypted, tag, plain);
    }

    fn expand(context: *anyopaque, algorithm: p.HashAlgorithm, key: []const u8, info: []const []const u8, out: []u8) p.ProviderError!void {
        const self = owner(context);
        self.expansions += 1;
        if (self.denial == .key_update_denied) return error.UnsupportedOperation;
        return self.standard.provider().vtable.hkdfExpand(context, algorithm, key, info, out);
    }
};

const Peer = struct {
    socket: *net.Socket,
    config: engine.ServerTLSConfig,
    scenario: Scenario,
    failure: ?anyerror = null,

    fn run(self: *@This()) void {
        self.exchange() catch |err| {
            self.failure = err;
        };
    }

    fn exchange(self: *@This()) !void {
        var connection = try engine.acceptServer(testing.allocator, self.socket, &.{"http/1.1"}, self.config);
        defer connection.deinit();
        var bytes: [32]u8 = undefined;
        try testing.expectEqualStrings("ping", bytes[0..try connection.read(&bytes)]);
        if (connection.tls_version == .tls_1_3 and (self.scenario == .round_trip or self.scenario == .key_update_denied)) {
            const update = [_]u8{ @intFromEnum(tls.HandshakeType.key_update), 0, 0, 1, 1 };
            try connection.writeEncryptedRecord(&update, .handshake);
            try record.updateTrafficKeys(connection.cryptoProvider(), connection.cipher_suite.?, &connection.app_write_secret.?, &connection.app_write_key.?, &connection.app_write_iv.?);
            connection.write_seq = 0;
        }
        try connection.writeAll("pong");
        try testing.expectEqualStrings("done", bytes[0..try connection.read(&bytes)]);
        try connection.writeAll("last");
    }
};

fn writeConnection(connection: *engine.Connection, bytes: []const u8, context: ?*const IoContext) !void {
    if (context) |io_context| return connection.writeAllWithContext(bytes, io_context);
    return connection.writeAll(bytes);
}

fn readConnection(connection: *engine.Connection, bytes: []u8, context: ?*const IoContext) !usize {
    if (context) |io_context| return connection.readWithContext(bytes, io_context);
    return connection.read(bytes);
}

fn exercise(version: tls.ProtocolVersion, scenario: Scenario, explicit_provider: bool, with_context: bool) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var root_key = try Ecdsa.KeyPair.generateDeterministic(@splat(1));
    defer p.secureWipeValue(&root_key);
    var leaf_key = try Ecdsa.KeyPair.generateDeterministic(@splat(3));
    defer p.secureWipeValue(&leaf_key);
    const root = try certificate(allocator, root_key, root_key, true);
    const leaf = try certificate(allocator, leaf_key, root_key, false);
    var server_config = try engine.ServerTLSConfig.init(testing.allocator, testing.io, &.{leaf}, .{
        .algorithm = .ecdsa_p256,
        .encoding = .raw_secret,
        .bytes = &leaf_key.secret_key.toBytes(),
    }, null);
    defer server_config.deinit();
    var listener = try net.TcpListener.init(try @import("../net/compat.zig").Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    var client_socket = try net.Socket.create();
    defer client_socket.close();
    try client_socket.connectWithTimeout(try listener.getLocalAddress(), 2000);
    try client_socket.setRecvTimeout(2000);
    try client_socket.setSendTimeout(2000);
    var accepted = try listener.accept();
    defer accepted.socket.close();
    try accepted.socket.setRecvTimeout(2000);
    try accepted.socket.setSendTimeout(2000);
    var peer: Peer = .{ .socket = &accepted.socket, .config = server_config, .scenario = scenario };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        client_socket.close();
        thread.join();
    };
    var observed: Observed = .{ .standard = .init(testing.io, testing.allocator), .version = version };
    var selected = observed.standard.provider();
    var vtable = selected.vtable.*;
    vtable.capabilities = Observed.capabilities;
    vtable.aeadSeal = Observed.seal;
    vtable.aeadOpen = Observed.open;
    vtable.hkdfExpand = Observed.expand;
    selected.vtable = &vtable;
    var certificate_crypto = engine.CryptoCertificateVerifier.init(selected);
    const config: engine.TLSConfig = .{
        .allocator = testing.allocator,
        .crypto_provider = if (explicit_provider) selected else null,
        .certificate_crypto = if (explicit_provider and scenario == .round_trip) &certificate_crypto else null,
        .server_authentication = .{ .verify = .{ .custom_only = .{ .der_certificates = &.{root} } } },
    };
    var connection = try engine.connectClient(testing.allocator, &client_socket, &config, "localhost");
    defer connection.deinit();
    try testing.expectEqual(version, connection.tlsVersion());
    try testing.expectEqualStrings("http/1.1", connection.negotiatedAlpn().?);
    if (explicit_provider) {
        try testing.expectEqual(selected.context, connection.crypto_provider.?.context);
        try testing.expectEqual(selected.vtable, connection.crypto_provider.?.vtable);
        try testing.expectEqual(selected.abi_version, connection.crypto_provider.?.abi_version);
    } else {
        try testing.expect(connection.crypto_provider == null);
        try testing.expectEqual(@as(*anyopaque, @ptrCast(&connection.standard_crypto_provider)), connection.cryptoProvider().context);
    }
    observed.seals = 0;
    observed.opens = 0;
    observed.expansions = 0;
    observed.denial = scenario;
    const io_context = IoContext.init(.{ .request_deadline = Deadline.afterMs(2000) });
    const context = if (with_context) &io_context else null;
    var bytes: [32]u8 = undefined;
    if (scenario == .seal_denied or scenario == .capability_denied) {
        const expected = if (scenario == .seal_denied) error.UnsupportedOperation else error.UnsupportedAlgorithm;
        try testing.expectError(expected, writeConnection(&connection, "ping", context));
        try testing.expectEqual(@as(usize, if (scenario == .seal_denied) 1 else 0), observed.seals);
        try testing.expect(connection.failed and connection.app_write_key == null);
        return;
    }
    try writeConnection(&connection, "ping", context);
    if (explicit_provider) try testing.expectEqual(@as(usize, 1), observed.seals);
    if (scenario == .open_denied or scenario == .key_update_denied) {
        try testing.expectError(error.UnsupportedOperation, readConnection(&connection, &bytes, context));
        try testing.expect(observed.opens > 0);
        if (scenario == .key_update_denied) try testing.expectEqual(@as(usize, 1), observed.expansions);
        try testing.expect(connection.failed and connection.app_read_key == null);
        return;
    }
    try testing.expectEqualStrings("pong", bytes[0..try readConnection(&connection, &bytes, context)]);
    if (explicit_provider) {
        try testing.expect(observed.opens > 0);
        if (version == .tls_1_3) {
            try testing.expect(observed.expansions >= 6);
            try testing.expect(observed.seals >= 2);
        }
    }
    try writeConnection(&connection, "done", context);
    try testing.expectEqualStrings("last", bytes[0..try readConnection(&connection, &bytes, context)]);
    thread.join();
    joined = true;
    if (peer.failure) |err| return err;
}

test "connectClient retains selected provider through authenticated records and key updates" {
    for ([_]tls.ProtocolVersion{ .tls_1_2, .tls_1_3 }) |version| {
        try exercise(version, .round_trip, true, false);
    }
}

test "connectClient preserves post-handshake provider restrictions and failures" {
    for ([_]tls.ProtocolVersion{ .tls_1_2, .tls_1_3 }) |version| {
        for ([_]Scenario{ .seal_denied, .open_denied, .capability_denied }) |scenario| {
            try exercise(version, scenario, true, false);
        }
    }
    try exercise(.tls_1_3, .key_update_denied, true, false);
}

test "connectClient default provider belongs to the returned connection" {
    try exercise(.tls_1_3, .round_trip, false, false);
}

test "connectClient context-aware records retain provider dispatch and fail closed" {
    for ([_]tls.ProtocolVersion{ .tls_1_2, .tls_1_3 }) |version| {
        for ([_]Scenario{ .round_trip, .seal_denied, .open_denied, .capability_denied }) |scenario| {
            try exercise(version, scenario, true, true);
        }
    }
    try exercise(.tls_1_3, .key_update_denied, true, true);
    try exercise(.tls_1_3, .round_trip, false, true);
}
