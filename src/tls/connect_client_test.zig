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
const trust = @import("trust.zig");
const metadata = @import("metadata_digest.zig");
const PolicyBinding = @import("policy_binding.zig").PolicyBinding;

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
const BindingCase = enum { paired, wrong_adapter, wrong_provider, wrong_provider_context, wrong_provider_vtable, policy_denied, backend_denied, hash_failed, signature_failed };

const Observed = struct {
    standard: Standard,
    version: tls.ProtocolVersion,
    denial: ?Scenario = null,
    seals: usize = 0,
    opens: usize = 0,
    expansions: usize = 0,
    binding_case: ?BindingCase = null,
    in_policy: bool = false,
    policy_calls: usize = 0,
    metadata_creates: usize = 0,
    metadata_updates: usize = 0,
    metadata_snapshots: usize = 0,
    metadata_destroys: usize = 0,
    policy_signatures: usize = 0,
    metadata_error: ?p.ProviderError = null,
    error_output_cleared: bool = false,

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
        if (self.binding_case == .backend_denied) result.setHash(.sha1, false);
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

    fn hashCreate(context: *anyopaque, allocator: std.mem.Allocator, algorithm: p.HashAlgorithm, out: *?*anyopaque) p.ProviderError!void {
        const self = owner(context);
        if (self.in_policy) self.metadata_creates += 1;
        return self.standard.provider().vtable.hashCreate(context, allocator, algorithm, out);
    }

    fn hashUpdate(context: *anyopaque, handle: *anyopaque, bytes: []const u8) p.ProviderError!void {
        const self = owner(context);
        if (self.in_policy) self.metadata_updates += 1;
        if (self.in_policy and self.binding_case == .hash_failed) return error.InternalError;
        return self.standard.provider().vtable.hashUpdate(context, handle, bytes);
    }

    fn hashSnapshot(context: *anyopaque, handle: *anyopaque, out: []u8) p.ProviderError!void {
        const self = owner(context);
        if (self.in_policy) self.metadata_snapshots += 1;
        return self.standard.provider().vtable.hashSnapshot(context, handle, out);
    }

    fn hashDestroy(context: *anyopaque, allocator: std.mem.Allocator, handle: *anyopaque) void {
        const self = owner(context);
        if (self.in_policy) self.metadata_destroys += 1;
        self.standard.provider().vtable.hashDestroy(context, allocator, handle);
    }

    fn verify(context: *anyopaque, scheme: p.SignatureScheme, key: p.PublicKey, parts: []const []const u8, signature_bytes: []const u8) p.ProviderError!void {
        const self = owner(context);
        if (self.in_policy) {
            self.policy_signatures += 1;
            if (self.binding_case == .signature_failed) return error.SignatureInvalid;
        }
        return self.standard.provider().vtable.verify(context, scheme, key, parts, signature_bytes);
    }
};

// Test-only exact fixture pin, identity/time checks and issuer signature.
// This exercises binding dispatch; it is not a replacement PKIX policy.
const FixturePolicy = struct {
    leaf: []const u8,
    issuer_spki: []const u8,
    tbs: []const u8,
    signature_bytes: []const u8,
    identifier: [20]u8,
    expected_verifier: trust.CertificateSignatureVerifier,
    observed: *Observed,

    fn verify(context: *const anyopaque, request: trust.VerifyPeerRequest, hasher: metadata.MetadataDigest) trust.TrustError!void {
        const self: *const @This() = @ptrCast(@alignCast(context));
        const observed = self.observed;
        observed.policy_calls += 1;
        if (request.signature_verifier.context != self.expected_verifier.context or
            request.signature_verifier.vtable != self.expected_verifier.vtable)
            return error.TlsInvalidTrustConfiguration;
        if (request.chain_der.len != 1 or !std.mem.eql(u8, self.leaf, request.chain_der[0])) return error.TlsUnknownCa;
        const identity = request.expected_identity orelse return error.TlsHostnameMismatch;
        if (identity != .dns_name or !std.mem.eql(u8, identity.dns_name, "localhost")) return error.TlsHostnameMismatch;
        if (request.now_seconds < 1_704_067_200) return error.TlsCertificateNotYetValid;
        if (request.now_seconds >= 2_524_608_000) return error.TlsCertificateExpired;
        const now = std.Io.Timestamp.now(testing.io, .real).toSeconds();
        if (request.now_seconds < now - 5 or request.now_seconds > now + 5) return error.TlsInvalidTrustConfiguration;
        observed.in_policy = true;
        defer observed.in_policy = false;
        var identifier: [20]u8 = @splat(0xa5);
        hasher.hash(request.scratch_allocator, .sha1, self.leaf, &identifier) catch |err| {
            observed.metadata_error = err;
            observed.error_output_cleared = std.mem.allEqual(u8, &identifier, 0);
            return if (err == error.OutOfMemory) error.OutOfMemory else error.TlsCertificateConstraintViolation;
        };
        if (!std.mem.eql(u8, &self.identifier, &identifier)) return error.TlsCertificateConstraintViolation;
        request.signature_verifier.verify(.{
            .algorithm = .{ .oid = "\x2a\x86\x48\xce\x3d\x04\x03\x02" },
            .issuer_spki_der = self.issuer_spki,
            .tbs_certificate_der = self.tbs,
            .signature = self.signature_bytes,
        }) catch return error.TlsCertificateSignatureInvalid;
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

fn exercise(version: tls.ProtocolVersion, scenario: Scenario, explicit_provider: bool, with_context: bool, binding_case: ?BindingCase) !void {
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
    var observed: Observed = .{ .standard = .init(testing.io, testing.allocator), .version = version, .binding_case = binding_case };
    var selected = observed.standard.provider();
    var vtable = selected.vtable.*;
    vtable.capabilities = Observed.capabilities;
    vtable.aeadSeal = Observed.seal;
    vtable.aeadOpen = Observed.open;
    vtable.hkdfExpand = Observed.expand;
    vtable.hashCreate = Observed.hashCreate;
    vtable.hashUpdate = Observed.hashUpdate;
    vtable.hashSnapshot = Observed.hashSnapshot;
    vtable.hashDestroy = Observed.hashDestroy;
    vtable.verify = Observed.verify;
    selected.vtable = &vtable;
    var certificate_crypto = engine.CryptoCertificateVerifier.init(selected);
    var other_adapter = engine.CryptoCertificateVerifier.init(selected);
    var other_provider = Standard.init(testing.io, testing.allocator);
    var other_observed: Observed = .{ .standard = .init(testing.io, testing.allocator), .version = version };
    var different_context = selected;
    different_context.context = other_observed.standard.provider().context;
    var copied_vtable = vtable;
    var different_vtable = selected;
    different_vtable.vtable = &copied_vtable;
    if (binding_case == .wrong_provider_context or binding_case == .wrong_provider_vtable) {
        const alternate = if (binding_case == .wrong_provider_context) different_context else different_vtable;
        try testing.expectEqualDeep(selected.vtable.capabilities(selected.context), alternate.vtable.capabilities(alternate.context));
        try testing.expectEqual(binding_case == .wrong_provider_vtable, selected.context == alternate.context);
        try testing.expectEqual(binding_case == .wrong_provider_context, selected.vtable == alternate.vtable);
    }
    var certificate_reader = try @import("crypto/der.zig").sequence(leaf);
    const leaf_tbs = try certificate_reader.element();
    _ = try certificate_reader.take(0x30);
    const leaf_signature = try certificate_reader.take(3);
    try certificate_reader.finish();
    const issuer_spki = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00".* ++ root_key.public_key.toUncompressedSec1();
    var policy: FixturePolicy = .{
        .leaf = leaf,
        .issuer_spki = &issuer_spki,
        .tbs = leaf_tbs.encoded,
        .signature_bytes = leaf_signature[1..],
        .identifier = undefined,
        .expected_verifier = certificate_crypto.verifier(),
        .observed = &observed,
    };
    std.crypto.hash.Sha1.hash(leaf, &policy.identifier, .{});
    var binding = try PolicyBinding.init(&policy, FixturePolicy.verify, certificate_crypto.verifier(), certificate_crypto.metadataHasher(.{
        .allow_sha1_identifiers = binding_case != .policy_denied,
    }));
    policy.expected_verifier = binding.signatureVerifier();
    const config: engine.TLSConfig = .{
        .allocator = testing.allocator,
        .crypto_provider = if (binding_case == .wrong_provider_context)
            different_context
        else if (binding_case == .wrong_provider_vtable)
            different_vtable
        else if (binding_case == .wrong_provider)
            other_provider.provider()
        else if (explicit_provider)
            selected
        else
            null,
        .certificate_crypto = if (binding_case == .wrong_adapter) &other_adapter else if (explicit_provider and (binding_case != null or scenario == .round_trip)) &certificate_crypto else null,
        .server_authentication = .{ .verify = if (binding_case != null)
            .{ .provider = binding.provider() }
        else
            .{ .custom_only = .{ .der_certificates = &.{root} } } },
    };
    if (binding_case) |case| {
        if (case != .wrong_adapter) {
            const configured_verifier = config.certificate_crypto.?.verifier();
            try testing.expectEqual(binding.signatureVerifier().context, configured_verifier.context);
            try testing.expectEqual(binding.signatureVerifier().vtable, configured_verifier.vtable);
        }
        if (case != .paired) {
            const expected = switch (case) {
                .wrong_adapter, .wrong_provider, .wrong_provider_context, .wrong_provider_vtable => error.TlsInvalidTrustConfiguration,
                .signature_failed => error.TlsCertificateSignatureInvalid,
                else => error.TlsCertificateConstraintViolation,
            };
            try testing.expectError(expected, engine.connectClient(testing.allocator, &client_socket, &config, "localhost"));
            const mismatched = case == .wrong_adapter or case == .wrong_provider or case == .wrong_provider_context or case == .wrong_provider_vtable;
            try testing.expectEqual(@as(usize, if (mismatched) 0 else 1), observed.policy_calls);
            try testing.expectEqual(@as(usize, if (case == .hash_failed or case == .signature_failed) 1 else 0), observed.metadata_creates);
            try testing.expectEqual(observed.metadata_creates, observed.metadata_updates);
            try testing.expectEqual(@as(usize, if (case == .signature_failed) 1 else 0), observed.metadata_snapshots);
            try testing.expectEqual(observed.metadata_creates, observed.metadata_destroys);
            try testing.expectEqual(@as(usize, if (case == .signature_failed) 1 else 0), observed.policy_signatures);
            if (case == .policy_denied or case == .backend_denied or case == .hash_failed) {
                try testing.expectEqual(if (case == .hash_failed) error.InternalError else error.UnsupportedAlgorithm, observed.metadata_error.?);
                try testing.expect(observed.error_output_cleared);
            }
            return;
        }
    }
    var connection = try engine.connectClient(testing.allocator, &client_socket, &config, "localhost");
    defer connection.deinit();
    if (binding_case == .paired) {
        try testing.expectEqual(@as(usize, 1), observed.policy_calls);
        try testing.expectEqual(@as(usize, 1), observed.metadata_creates);
        try testing.expectEqual(@as(usize, 1), observed.metadata_updates);
        try testing.expectEqual(@as(usize, 1), observed.metadata_snapshots);
        try testing.expectEqual(@as(usize, 1), observed.metadata_destroys);
        try testing.expectEqual(@as(usize, 1), observed.policy_signatures);
    }
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
        try exercise(version, .round_trip, true, false, null);
    }
}

test "connectClient preserves post-handshake provider restrictions and failures" {
    for ([_]tls.ProtocolVersion{ .tls_1_2, .tls_1_3 }) |version| {
        for ([_]Scenario{ .seal_denied, .open_denied, .capability_denied }) |scenario| {
            try exercise(version, scenario, true, false, null);
        }
    }
    try exercise(.tls_1_3, .key_update_denied, true, false, null);
}

test "connectClient default provider belongs to the returned connection" {
    try exercise(.tls_1_3, .round_trip, false, false, null);
}

test "connectClient context-aware records retain provider dispatch and fail closed" {
    for ([_]tls.ProtocolVersion{ .tls_1_2, .tls_1_3 }) |version| {
        for ([_]Scenario{ .round_trip, .seal_denied, .open_denied, .capability_denied }) |scenario| {
            try exercise(version, scenario, true, true, null);
        }
    }
    try exercise(.tls_1_3, .key_update_denied, true, true, null);
    try exercise(.tls_1_3, .round_trip, false, true, null);
}

test "connectClient uses the exact policy binding through metadata signatures records and failures" {
    for ([_]tls.ProtocolVersion{ .tls_1_2, .tls_1_3 }) |version| {
        for (std.enums.values(BindingCase)) |case| {
            try exercise(version, .round_trip, true, false, case);
        }
        for ([_]Scenario{ .seal_denied, .open_denied, .capability_denied }) |scenario| {
            try exercise(version, scenario, true, false, .paired);
        }
    }
    try exercise(.tls_1_3, .key_update_denied, true, false, .paired);
}
