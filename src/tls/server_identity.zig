//! A configuration-owned signing handle. Certificate trust is deliberately
//! separate; this module verifies only that the configured key pair matches.
const std = @import("std");
const p = @import("crypto/provider.zig");
const StandardProvider = @import("crypto/standard.zig").StandardProvider;
const algorithms = @import("crypto/algorithm_encoding.zig");
const der = @import("crypto/der.zig");

pub const Identity = struct {
    allocator: std.mem.Allocator,
    standard: StandardProvider,
    crypto: p.CryptoProvider,
    key: p.SigningKey,
    schemes: p.Capabilities,
    uses_standard: bool,
    mutex: std.Io.Mutex = .init,

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        selected: ?p.CryptoProvider,
        public_key: p.PublicKey,
        public_restrictions: ?algorithms.PssParameters,
        private_key: p.PrivateKey,
    ) !*Identity {
        if (private_key.algorithm != public_key.algorithm) return error.TlsCertificateKeyMismatch;
        const private_restrictions = try privateRestrictions(private_key);
        const self = try allocator.create(Identity);
        errdefer {
            p.secureWipeValue(self);
            allocator.destroy(self);
        }
        self.allocator = allocator;
        self.standard = StandardProvider.init(io, allocator);
        self.crypto = selected orelse self.standard.provider();
        self.uses_standard = selected == null;
        self.mutex = .init;
        self.schemes = try self.crypto.capabilities();
        var verification_scheme: ?p.SignatureScheme = null;
        for (std.enums.values(p.SignatureScheme)) |scheme| {
            const allowed = scheme != .rsa_pkcs1_sha1 and scheme.keyAlgorithm() == public_key.algorithm and
                self.schemes.supportsSign(scheme) and self.schemes.supportsVerify(scheme) and
                restrictionsAllow(public_restrictions, scheme) and restrictionsAllow(private_restrictions, scheme);
            self.schemes.setSign(scheme, allowed);
            if (allowed and verification_scheme == null) verification_scheme = scheme;
        }
        const scheme = verification_scheme orelse return error.UnsupportedAlgorithm;
        self.key = try self.crypto.signingKeyImport(allocator, private_key);
        errdefer self.key.deinit();
        var challenge: [32]u8 = undefined;
        defer p.secureWipe(&challenge);
        try self.crypto.random(&challenge);
        var signature_buffer: [512]u8 = undefined;
        defer p.secureWipe(&signature_buffer);
        const parts = &.{ "HTTPX configured TLS identity", &challenge };
        const signature = try self.key.sign(scheme, parts, &signature_buffer);
        self.crypto.verify(scheme, public_key, parts, signature) catch |err| switch (err) {
            error.SignatureInvalid => return error.TlsCertificateKeyMismatch,
            else => return err,
        };
        return self;
    }

    pub fn supports(self: *const Identity, scheme: p.SignatureScheme) bool {
        return self.schemes.supportsSign(scheme);
    }

    pub fn sign(self: *Identity, io: std.Io, scheme: p.SignatureScheme, parts: []const []const u8, output: []u8) ![]u8 {
        if (!self.supports(scheme)) return error.UnsupportedAlgorithm;
        try self.mutex.lock(io);
        defer self.mutex.unlock(io);
        if (self.uses_standard) self.standard.io = io;
        return self.key.sign(scheme, parts, output);
    }

    /// The owner must wait for all concurrent signing operations before release.
    pub fn destroy(self: *Identity) void {
        const allocator = self.allocator;
        self.key.deinit();
        p.secureWipeValue(self);
        allocator.destroy(self);
    }
};

fn restrictionsAllow(restrictions: ?algorithms.PssParameters, scheme: p.SignatureScheme) bool {
    const parameters = restrictions orelse return true;
    if (scheme.keyAlgorithm() != .rsa_pss) return false;
    const hash = scheme.hashAlgorithm() orelse return false;
    return parameters.hash == hash and parameters.mgf_hash == hash and
        parameters.salt_length <= hash.digestLength() and parameters.trailer == 1;
}

fn privateRestrictions(key: p.PrivateKey) !?algorithms.PssParameters {
    if (key.algorithm != .rsa_pss or key.encoding != .pkcs8_der) return null;
    if (key.bytes.len > 16 * 1024) return error.InvalidEncoding;
    var container = try der.sequence(key.bytes);
    _ = try container.take(2);
    var identifier: der.Reader = .{ .bytes = try container.take(0x30) };
    if (!std.mem.eql(u8, try identifier.take(6), algorithms.pss_oid)) return error.InvalidEncoding;
    if (identifier.offset == identifier.bytes.len) return null;
    const parameters = try identifier.element();
    try identifier.finish();
    return try algorithms.parsePss(parameters.encoded);
}

pub fn privateEncoding(algorithm: p.SignatureKeyAlgorithm, bytes: []const u8) !p.PrivateKeyEncoding {
    if (bytes.len > 16 * 1024) return error.InvalidEncoding;
    var container = try der.sequence(bytes);
    _ = try container.take(2);
    if (container.offset >= container.bytes.len) return error.InvalidEncoding;
    if (container.bytes[container.offset] == 0x30) return .pkcs8_der;
    return switch (algorithm) {
        .rsa, .rsa_pss => .rsa_pkcs1_der,
        .ecdsa_p256, .ecdsa_p384 => .sec1_der,
        .ed25519 => error.InvalidEncoding,
    };
}

test "server identity verifies ownership through the selected signing provider" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const secret: [32]u8 = @splat(1);
    const pair = try Ecdsa.KeyPair.fromSecretKey(.{ .bytes = secret });
    const public_bytes = pair.public_key.toUncompressedSec1();
    const public: p.PublicKey = .{ .algorithm = .ecdsa_p256, .encoding = .sec1_uncompressed, .bytes = &public_bytes };
    const private: p.PrivateKey = .{ .algorithm = .ecdsa_p256, .encoding = .raw_secret, .bytes = &secret };
    const Observer = struct {
        standard: StandardProvider,
        signs: usize = 0,
        verifies: usize = 0,

        fn sign(context: *anyopaque, handle: *anyopaque, scheme: p.SignatureScheme, parts: []const []const u8, output: []u8) p.ProviderError!usize {
            const standard: *StandardProvider = @ptrCast(@alignCast(context));
            const self: *@This() = @fieldParentPtr("standard", standard);
            self.signs += 1;
            return self.standard.provider().vtable.sign(context, handle, scheme, parts, output);
        }

        fn verify(context: *anyopaque, scheme: p.SignatureScheme, key: p.PublicKey, parts: []const []const u8, signature: []const u8) p.ProviderError!void {
            const standard: *StandardProvider = @ptrCast(@alignCast(context));
            const self: *@This() = @fieldParentPtr("standard", standard);
            self.verifies += 1;
            return self.standard.provider().vtable.verify(context, scheme, key, parts, signature);
        }
    };
    var observed: Observer = .{ .standard = StandardProvider.init(std.testing.io, std.testing.allocator) };
    var table = observed.standard.provider().vtable.*;
    table.sign = Observer.sign;
    table.verify = Observer.verify;
    const provider = p.CryptoProvider.init(&observed.standard, &table);
    const identity = try Identity.create(std.testing.allocator, std.testing.io, provider, public, null, private);
    defer identity.destroy();
    try std.testing.expectEqual(1, observed.signs);
    try std.testing.expectEqual(1, observed.verifies);
    var output: [72]u8 = undefined;
    const signature = try identity.sign(std.testing.io, .ecdsa_secp256r1_sha256, &.{"server signature"}, &output);
    try provider.verify(.ecdsa_secp256r1_sha256, public, &.{"server signature"}, signature);
    try std.testing.expectEqual(2, observed.signs);
    try std.testing.expectError(error.UnsupportedAlgorithm, identity.sign(std.testing.io, .rsa_pss_rsae_sha256, &.{"wrong scheme"}, &output));
    const other_secret: [32]u8 = @splat(2);
    try std.testing.expectError(error.TlsCertificateKeyMismatch, Identity.create(std.testing.allocator, std.testing.io, provider, public, null, .{
        .algorithm = .ecdsa_p256,
        .encoding = .raw_secret,
        .bytes = &other_secret,
    }));
    try std.testing.expectError(error.OutOfMemory, Identity.create(std.testing.failing_allocator, std.testing.io, provider, public, null, private));
}

test "server identity serializes a shared mutable provider signing handle" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const secret: [32]u8 = @splat(1);
    const pair = try Ecdsa.KeyPair.fromSecretKey(.{ .bytes = secret });
    const public_bytes = pair.public_key.toUncompressedSec1();
    const Checked = struct {
        standard: StandardProvider,
        active: std.atomic.Value(bool) = .init(false),

        fn sign(context: *anyopaque, key: *anyopaque, scheme: p.SignatureScheme, parts: []const []const u8, output: []u8) p.ProviderError!usize {
            const standard: *StandardProvider = @ptrCast(@alignCast(context));
            const self: *@This() = @fieldParentPtr("standard", standard);
            if (self.active.swap(true, .seq_cst)) return error.SigningFailed;
            defer self.active.store(false, .seq_cst);
            std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake) catch return error.SigningFailed;
            return self.standard.provider().vtable.sign(context, key, scheme, parts, output);
        }
    };
    var checked: Checked = .{ .standard = StandardProvider.init(std.testing.io, std.testing.allocator) };
    var table = checked.standard.provider().vtable.*;
    table.sign = Checked.sign;
    const identity = try Identity.create(
        std.testing.allocator,
        std.testing.io,
        p.CryptoProvider.init(&checked.standard, &table),
        .{ .algorithm = .ecdsa_p256, .encoding = .sec1_uncompressed, .bytes = &public_bytes },
        null,
        .{ .algorithm = .ecdsa_p256, .encoding = .raw_secret, .bytes = &secret },
    );
    defer identity.destroy();
    var failed: std.atomic.Value(bool) = .init(false);
    const Worker = struct {
        fn run(shared: *Identity, failure: *std.atomic.Value(bool)) void {
            for (0..8) |_| {
                var output: [72]u8 = undefined;
                _ = shared.sign(std.testing.io, .ecdsa_secp256r1_sha256, &.{"parallel handshake proof"}, &output) catch {
                    failure.store(true, .seq_cst);
                    return;
                };
            }
        }
    };
    {
        var threads: [4]std.Thread = undefined;
        var started: usize = 0;
        defer for (threads[0..started]) |thread| thread.join();
        for (&threads) |*thread| {
            thread.* = try std.Thread.spawn(.{}, Worker.run, .{ identity, &failed });
            started += 1;
        }
    }
    try std.testing.expect(!failed.load(.seq_cst));
}
