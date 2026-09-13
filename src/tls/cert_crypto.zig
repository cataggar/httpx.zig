//! Adapts certificate signatures to a selected CryptoProvider. Trust, name,
//! validity, usage and path-constraint decisions remain with TrustProvider.
const std = @import("std");
const signature = @import("cert_signature.zig");
const p = @import("crypto/provider.zig");
const der = @import("crypto/der.zig");
const algorithm_encoding = @import("crypto/algorithm_encoding.zig");
const Error = signature.CertificateSignatureError;
const Certificate = std.crypto.Certificate;

pub const MetadataDigestOptions = struct {
    allow_sha1_identifiers: bool = false,
};

/// Borrowed adapter. Keep this object at a stable address and keep the
/// underlying crypto provider alive for every verification using the handle.
/// No allocation or mutable per-call state is retained by the adapter.
pub const CryptoCertificateVerifier = struct {
    crypto: p.CryptoProvider,

    pub fn init(crypto: p.CryptoProvider) CryptoCertificateVerifier {
        return .{ .crypto = crypto };
    }

    pub fn verifier(self: *CryptoCertificateVerifier) signature.CertificateSignatureVerifier {
        return .{ .context = self, .vtable = &.{ .verify = verify } };
    }

    /// Hashes public trust-store identifiers, not certificate signatures.
    /// No slices or hash state survive this synchronous call.
    pub fn digestMetadata(
        self: *const CryptoCertificateVerifier,
        scratch: std.mem.Allocator,
        algorithm: p.HashAlgorithm,
        input: []const u8,
        out: []u8,
        options: MetadataDigestOptions,
    ) p.ProviderError!void {
        errdefer p.secureWipe(out);
        if (out.len != algorithm.digestLength()) return error.InvalidDigestLength;
        if (algorithm == .sha1 and !options.allow_sha1_identifiers) return error.UnsupportedAlgorithm;
        var hash = try self.crypto.hashCreate(scratch, algorithm);
        defer hash.deinit();
        try hash.update(input);
        try hash.snapshot(out);
    }

    fn verify(context: *anyopaque, request: signature.VerifyCertificateSignatureRequest) Error!void {
        const self: *const CryptoCertificateVerifier = @ptrCast(@alignCast(context));
        var scheme = try signatureScheme(request.algorithm);
        const key = try publicKey(request.issuer_spki_der);
        if (key.algorithm == .rsa_pss) {
            if (!std.mem.eql(u8, request.algorithm.oid, pss_oid)) return error.UnsupportedAlgorithm;
            const params = try parsePss(request.algorithm.parameters_der orelse return error.MalformedAlgorithmIdentifier);
            const restrictions = pssKeyRestrictions(request.issuer_spki_der) catch return error.MalformedSubjectPublicKeyInfo;
            if (restrictions) |restriction| {
                if (params.hash != restriction.hash or params.mgf_hash != restriction.mgf_hash or
                    params.salt_length < restriction.salt_length or params.trailer != restriction.trailer)
                    return error.UnsupportedAlgorithm;
            }
            scheme = switch (scheme) {
                .rsa_pss_rsae_sha256 => .rsa_pss_pss_sha256,
                .rsa_pss_rsae_sha384 => .rsa_pss_pss_sha384,
                .rsa_pss_rsae_sha512 => .rsa_pss_pss_sha512,
                else => return error.UnsupportedAlgorithm,
            };
        }
        if (scheme.keyAlgorithm() != key.algorithm) return error.UnsupportedAlgorithm;
        self.crypto.verify(scheme, key, &.{request.tbs_certificate_der}, request.signature) catch |err| switch (err) {
            error.UnsupportedAlgorithm, error.UnsupportedOperation => return error.UnsupportedAlgorithm,
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidPublicKeyLength => return error.MalformedSubjectPublicKeyInfo,
            else => return error.InvalidSignature,
        };
    }
};

fn signatureScheme(algorithm: signature.AlgorithmIdentifier) Error!p.SignatureScheme {
    if (std.mem.eql(u8, algorithm.oid, pss_oid)) {
        const params = try parsePss(algorithm.parameters_der orelse return error.MalformedAlgorithmIdentifier);
        if (params.hash != params.mgf_hash or params.salt_length != params.hash.digestLength() or params.trailer != 1)
            return error.UnsupportedAlgorithm;
        return switch (params.hash) {
            .sha256 => .rsa_pss_rsae_sha256,
            .sha384 => .rsa_pss_rsae_sha384,
            .sha512 => .rsa_pss_rsae_sha512,
            .sha1 => error.UnsupportedAlgorithm,
        };
    }
    const id = Certificate.Algorithm.map.get(algorithm.oid) orelse return error.UnsupportedAlgorithm;
    switch (id) {
        .sha1WithRSAEncryption => return error.UnsupportedAlgorithm,
        .sha256WithRSAEncryption, .sha384WithRSAEncryption, .sha512WithRSAEncryption => {
            if (algorithm.parameters_der) |params| {
                if (!std.mem.eql(u8, params, "\x05\x00")) return error.MalformedAlgorithmIdentifier;
            }
        },
        .ecdsa_with_SHA256, .ecdsa_with_SHA384, .curveEd25519 => {
            if (algorithm.parameters_der != null) return error.MalformedAlgorithmIdentifier;
        },
        else => return error.UnsupportedAlgorithm,
    }
    return switch (id) {
        .sha256WithRSAEncryption => .rsa_pkcs1_sha256,
        .sha384WithRSAEncryption => .rsa_pkcs1_sha384,
        .sha512WithRSAEncryption => .rsa_pkcs1_sha512,
        .ecdsa_with_SHA256 => .ecdsa_secp256r1_sha256,
        .ecdsa_with_SHA384 => .ecdsa_secp384r1_sha384,
        .curveEd25519 => .ed25519,
        else => unreachable,
    };
}

fn publicKey(bytes: []const u8) Error!p.PublicKey {
    return parsePublicKey(bytes) catch |err| switch (err) {
        error.InvalidEncoding => error.MalformedSubjectPublicKeyInfo,
        error.UnsupportedAlgorithm => error.UnsupportedAlgorithm,
    };
}

pub fn parsePublicKey(bytes: []const u8) (der.Error || error{UnsupportedAlgorithm})!p.PublicKey {
    return (try parsePublicKeyInfo(bytes)).key;
}

pub const PublicKeyInfo = struct {
    key: p.PublicKey,
    pss_parameters: ?PssParameters = null,
};

pub fn parsePublicKeyInfo(bytes: []const u8) (der.Error || error{UnsupportedAlgorithm})!PublicKeyInfo {
    if (bytes.len > 4096) return error.InvalidEncoding;
    var spki = try der.sequence(bytes);
    var algorithm: der.Reader = .{ .bytes = try spki.take(0x30) };
    const oid = try algorithm.take(0x06);
    const bits = try spki.take(0x03);
    try spki.finish();
    if (bits.len < 2 or bits[0] != 0) return error.InvalidEncoding;
    const id = Certificate.AlgorithmCategory.map.get(oid) orelse return error.UnsupportedAlgorithm;
    var pss_parameters: ?PssParameters = null;
    const key: p.PublicKey = switch (id) {
        .rsaEncryption => blk: {
            if (algorithm.offset != algorithm.bytes.len) {
                const parameters = try algorithm.take(0x05);
                if (parameters.len != 0) return error.InvalidEncoding;
            }
            try der.validateRsaPublicKey(bits[1..]);
            break :blk .{ .algorithm = .rsa, .encoding = .rsa_pkcs1_der, .bytes = bits[1..] };
        },
        .X9_62_id_ecPublicKey => blk: {
            const curve_oid = try algorithm.take(0x06);
            const curve = Certificate.NamedCurve.map.get(curve_oid) orelse return error.UnsupportedAlgorithm;
            const key_algorithm: p.SignatureKeyAlgorithm = switch (curve) {
                .X9_62_prime256v1 => .ecdsa_p256,
                .secp384r1 => .ecdsa_p384,
                else => return error.UnsupportedAlgorithm,
            };
            const expected_length: usize = if (key_algorithm == .ecdsa_p256) 65 else 97;
            if (bits.len != 1 + expected_length or bits[1] != 4) return error.InvalidEncoding;
            break :blk .{ .algorithm = key_algorithm, .encoding = .sec1_uncompressed, .bytes = bits[1..] };
        },
        .curveEd25519 => blk: {
            if (bits.len != 33) return error.InvalidEncoding;
            break :blk .{ .algorithm = .ed25519, .encoding = .ed25519_raw, .bytes = bits[1..] };
        },
        .rsassa_pss => blk: {
            if (algorithm.offset < algorithm.bytes.len) {
                const params = try algorithm.element();
                pss_parameters = parsePss(params.encoded) catch |err| switch (err) {
                    error.UnsupportedAlgorithm => return error.UnsupportedAlgorithm,
                    else => return error.InvalidEncoding,
                };
            }
            try der.validateRsaPublicKey(bits[1..]);
            break :blk .{ .algorithm = .rsa_pss, .encoding = .rsa_pkcs1_der, .bytes = bits[1..] };
        },
    };
    try algorithm.finish();
    return .{ .key = key, .pss_parameters = pss_parameters };
}

const pss_oid = algorithm_encoding.pss_oid;
pub const PssParameters = algorithm_encoding.PssParameters;

pub fn parsePss(bytes: []const u8) Error!PssParameters {
    return algorithm_encoding.parsePss(bytes) catch |err| switch (err) {
        error.InvalidEncoding => error.MalformedAlgorithmIdentifier,
        error.UnsupportedAlgorithm => error.UnsupportedAlgorithm,
    };
}

fn pssKeyRestrictions(bytes: []const u8) Error!?PssParameters {
    var spki = der.sequence(bytes) catch return error.MalformedSubjectPublicKeyInfo;
    var algorithm: der.Reader = .{ .bytes = spki.take(0x30) catch return error.MalformedSubjectPublicKeyInfo };
    _ = algorithm.take(0x06) catch return error.MalformedSubjectPublicKeyInfo;
    if (algorithm.offset == algorithm.bytes.len) return null;
    const params = algorithm.element() catch return error.MalformedSubjectPublicKeyInfo;
    return try parsePss(params.encoded);
}

fn testPssParameters(comptime hash: u8, comptime mgf_hash: u8, comptime salt: u8) [54]u8 {
    return "\x30\x34\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02".* ++
        [_]u8{hash} ++ "\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02".* ++
        [_]u8{mgf_hash} ++ "\x05\x00\xa2\x03\x02\x01".* ++ [_]u8{salt};
}

test "certificate bridge validates RSA-PSS hash MGF salt and canonical parameters" {
    const testing = std.testing;
    try testing.expectEqual(p.SignatureScheme.rsa_pss_rsae_sha256, try signatureScheme(.{ .oid = pss_oid, .parameters_der = &testPssParameters(1, 1, 32) }));
    try testing.expectEqual(p.SignatureScheme.rsa_pss_rsae_sha384, try signatureScheme(.{ .oid = pss_oid, .parameters_der = &testPssParameters(2, 2, 48) }));
    try testing.expectEqual(p.SignatureScheme.rsa_pss_rsae_sha512, try signatureScheme(.{ .oid = pss_oid, .parameters_der = &testPssParameters(3, 3, 64) }));
    try testing.expectError(error.UnsupportedAlgorithm, signatureScheme(.{ .oid = pss_oid, .parameters_der = &testPssParameters(1, 2, 32) }));
    try testing.expectError(error.UnsupportedAlgorithm, signatureScheme(.{ .oid = pss_oid, .parameters_der = &testPssParameters(1, 1, 31) }));
    try testing.expectError(error.UnsupportedAlgorithm, signatureScheme(.{ .oid = pss_oid, .parameters_der = "\x30\x00" }));
    try testing.expectError(error.MalformedAlgorithmIdentifier, signatureScheme(.{ .oid = pss_oid }));
    const parameters = testPssParameters(1, 1, 32);
    for (0..parameters.len) |length| {
        try testing.expectError(error.MalformedAlgorithmIdentifier, parsePss(parameters[0..length]));
    }
}

test "certificate bridge enforces restricted PSS key parameters before dispatch" {
    const parameters = testPssParameters(2, 2, 48);
    const spki = "\x30\x4e\x30\x41\x06\x09".* ++ pss_oid.* ++ parameters ++
        "\x03\x09\x00\x30\x06\x02\x01\x01\x02\x01\x03".*;
    const parsed = try parsePublicKey(&spki);
    try std.testing.expectEqual(p.SignatureKeyAlgorithm.rsa_pss, parsed.algorithm);
    var standard = @import("crypto/standard.zig").StandardProvider.init(std.testing.io, std.testing.allocator);
    var adapter = CryptoCertificateVerifier.init(standard.provider());
    try std.testing.expectError(error.UnsupportedAlgorithm, adapter.verifier().verify(.{
        .algorithm = .{ .oid = pss_oid, .parameters_der = &testPssParameters(1, 1, 32) },
        .issuer_spki_der = &spki,
        .tbs_certificate_der = "not signed",
        .signature = "not a signature",
    }));
}

/// Extracts only the leaf SPKI needed for TLS proof-of-possession. Certificate
/// policy and signatures are checked independently by the trust provider.
pub fn certificatePublicKey(bytes: []const u8) (der.Error || error{UnsupportedAlgorithm})!p.PublicKey {
    return (try certificatePublicKeyInfo(bytes)).key;
}

pub fn certificatePublicKeyInfo(bytes: []const u8) (der.Error || error{UnsupportedAlgorithm})!PublicKeyInfo {
    if (bytes.len > 256 * 1024) return error.InvalidEncoding;
    var certificate = try der.sequence(bytes);
    var tbs: der.Reader = .{ .bytes = try certificate.take(0x30) };
    _ = try certificate.take(0x30);
    const signature_bits = try certificate.take(0x03);
    if (signature_bits.len < 2 or signature_bits[0] != 0) return error.InvalidEncoding;
    try certificate.finish();
    if (tbs.bytes.len > 0 and tbs.bytes[0] == 0xa0) _ = try tbs.take(0xa0);
    _ = try tbs.take(0x02);
    _ = try tbs.take(0x30);
    _ = try tbs.take(0x30);
    _ = try tbs.take(0x30);
    _ = try tbs.take(0x30);
    const start = tbs.offset;
    _ = try tbs.take(0x30);
    return parsePublicKeyInfo(tbs.bytes[start..tbs.offset]);
}

test "certificate bridge verifies ECDSA through selected standard provider" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const key = try Ecdsa.KeyPair.generateDeterministic(@splat(0x42));
    const spki = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00".* ++ key.public_key.toUncompressedSec1();
    const signed = try key.sign("exact TBS DER", null);
    var encoded: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const bytes = signed.toDer(&encoded);
    var standard = @import("crypto/standard.zig").StandardProvider.init(std.testing.io, std.testing.allocator);
    var adapter = CryptoCertificateVerifier.init(standard.provider());
    const request: signature.VerifyCertificateSignatureRequest = .{
        .algorithm = .{ .oid = "\x2a\x86\x48\xce\x3d\x04\x03\x02" },
        .issuer_spki_der = &spki,
        .tbs_certificate_der = "exact TBS DER",
        .signature = bytes,
    };
    try adapter.verifier().verify(request);
    var wrong_message = request;
    wrong_message.tbs_certificate_der = "different TBS DER";
    try std.testing.expectError(error.InvalidSignature, adapter.verifier().verify(wrong_message));
    for (0..spki.len) |length| {
        var truncated = request;
        truncated.issuer_spki_der = spki[0..length];
        try std.testing.expectError(error.MalformedSubjectPublicKeyInfo, adapter.verifier().verify(truncated));
    }
}

test "certificate bridge supports P384 and Ed25519 certificate edges" {
    var standard = @import("crypto/standard.zig").StandardProvider.init(std.testing.io, std.testing.allocator);
    var adapter = CryptoCertificateVerifier.init(standard.provider());
    inline for (.{ std.crypto.sign.ecdsa.EcdsaP384Sha384, std.crypto.sign.Ed25519 }) |Scheme| {
        const is_ed25519 = Scheme == std.crypto.sign.Ed25519;
        const key = try Scheme.KeyPair.generateDeterministic(@splat(0x42));
        const spki = if (is_ed25519)
            "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00".* ++ key.public_key.toBytes()
        else
            "\x30\x76\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x22\x03\x62\x00".* ++ key.public_key.toUncompressedSec1();
        const signed = try key.sign("TBS DER", null);
        var encoded: [104]u8 = undefined;
        const bytes = if (is_ed25519) &signed.toBytes() else signed.toDer(&encoded);
        try adapter.verifier().verify(.{
            .algorithm = .{ .oid = if (is_ed25519) "\x2b\x65\x70" else "\x2a\x86\x48\xce\x3d\x04\x03\x03" },
            .issuer_spki_der = &spki,
            .tbs_certificate_der = "TBS DER",
            .signature = bytes,
        });
    }
}

test "certificate bridge fails closed on malformed SPKI and algorithm parameters" {
    var standard = @import("crypto/standard.zig").StandardProvider.init(std.testing.io, std.testing.allocator);
    var adapter = CryptoCertificateVerifier.init(standard.provider());
    var request: signature.VerifyCertificateSignatureRequest = .{
        .algorithm = .{ .oid = "\x2a\x86\x48\xce\x3d\x04\x03\x02" },
        .issuer_spki_der = "",
        .tbs_certificate_der = "",
        .signature = "",
    };
    for ([_][]const u8{ "", "\x30", "\x30\x00", "\x30\x01\x30", "\x30\x80", "\x30\x82\x10\x00" }) |bytes| {
        request.issuer_spki_der = bytes;
        try std.testing.expectError(error.MalformedSubjectPublicKeyInfo, adapter.verifier().verify(request));
    }
    request.algorithm.parameters_der = "\x05\x00";
    try std.testing.expectError(error.MalformedAlgorithmIdentifier, adapter.verifier().verify(request));
    request.algorithm = .{ .oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a" };
    try std.testing.expectError(error.MalformedAlgorithmIdentifier, adapter.verifier().verify(request));
    request.algorithm = .{ .oid = "\x2a\x03\x04" };
    try std.testing.expectError(error.UnsupportedAlgorithm, adapter.verifier().verify(request));
}

test "certificate bridge never falls back after provider rejection" {
    const Reject = struct {
        calls: usize = 0,
        input_matches: bool = false,

        fn verify(context: *anyopaque, scheme: p.SignatureScheme, key: p.PublicKey, parts: []const []const u8, encoded: []const u8) p.ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            self.input_matches = scheme == .ed25519 and key.algorithm == .ed25519 and
                key.encoding == .ed25519_raw and key.bytes.len == 32 and encoded.len == 64 and
                parts.len == 1 and std.mem.eql(u8, parts[0], "TBS");
            return error.UnsupportedOperation;
        }
    };
    var reject = Reject{};
    var standard = @import("crypto/standard.zig").StandardProvider.init(std.testing.io, std.testing.allocator);
    const original = standard.provider();
    var vtable = original.vtable.*;
    vtable.verify = Reject.verify;
    var adapter = CryptoCertificateVerifier.init(p.CryptoProvider.init(&reject, &vtable));
    const key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x42));
    const spki = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00".* ++ key.public_key.toBytes();
    const signed = try key.sign("TBS", null);
    try std.testing.expectError(error.UnsupportedAlgorithm, adapter.verifier().verify(.{
        .algorithm = .{ .oid = "\x2b\x65\x70" },
        .issuer_spki_der = &spki,
        .tbs_certificate_der = "TBS",
        .signature = &signed.toBytes(),
    }));
    try std.testing.expectEqual(@as(usize, 1), reject.calls);
    try std.testing.expect(reject.input_matches);
}

test "certificate metadata digest routes supported hashes and gates SHA1 independently" {
    const testing = std.testing;
    var standard = @import("crypto/standard.zig").StandardProvider.init(testing.io, testing.allocator);
    const provider = standard.provider();
    const before = try provider.capabilities();
    var adapter = CryptoCertificateVerifier.init(provider);
    var sha1: [20]u8 = @splat(0xa5);
    try testing.expectError(error.UnsupportedAlgorithm, adapter.digestMetadata(testing.allocator, .sha1, "abc", &sha1, .{}));
    try testing.expectEqualSlices(u8, &(@as([20]u8, @splat(0))), &sha1);
    try adapter.digestMetadata(testing.allocator, .sha1, "abc", &sha1, .{ .allow_sha1_identifiers = true });
    try testing.expectEqualSlices(u8, "\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d", &sha1);
    inline for (.{
        .{ p.HashAlgorithm.sha256, std.crypto.hash.sha2.Sha256 },
        .{ p.HashAlgorithm.sha384, std.crypto.hash.sha2.Sha384 },
        .{ p.HashAlgorithm.sha512, std.crypto.hash.sha2.Sha512 },
    }) |case| {
        var actual: [case[0].digestLength()]u8 = undefined;
        var expected: [case[0].digestLength()]u8 = undefined;
        case[1].hash("abc", &expected, .{});
        try adapter.digestMetadata(testing.allocator, case[0], "abc", &actual, .{});
        try testing.expectEqualSlices(u8, &expected, &actual);
    }
    try testing.expect(std.meta.eql(before, try provider.capabilities()));
    try testing.expectError(error.UnsupportedAlgorithm, adapter.verifier().verify(.{
        .algorithm = .{ .oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05", .parameters_der = "\x05\x00" },
        .issuer_spki_der = "",
        .tbs_certificate_der = "",
        .signature = "",
    }));
}

test "certificate metadata digest requires exact output and clears allocation failures" {
    const testing = std.testing;
    var standard = @import("crypto/standard.zig").StandardProvider.init(testing.io, testing.allocator);
    const adapter = CryptoCertificateVerifier.init(standard.provider());
    var bytes: [65]u8 = undefined;
    for ([_]usize{ 0, 1, 31, 33, 64, 65 }) |size| {
        @memset(&bytes, 0xa5);
        try testing.expectError(error.InvalidDigestLength, adapter.digestMetadata(testing.allocator, .sha256, "abc", bytes[0..size], .{}));
        try testing.expect(std.mem.allEqual(u8, bytes[0..size], 0));
        try testing.expect(std.mem.allEqual(u8, bytes[size..], 0xa5));
    }
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    @memset(&bytes, 0xa5);
    try testing.expectError(error.OutOfMemory, adapter.digestMetadata(failing.allocator(), .sha256, "abc", bytes[0..32], .{}));
    try testing.expect(std.mem.allEqual(u8, bytes[0..32], 0));
}

test "certificate metadata digest preserves hash callback failures and destroys per-call state" {
    const testing = std.testing;
    const Observed = struct {
        const Self = @This();
        const Standard = @import("crypto/standard.zig").StandardProvider;
        const Failure = enum { create, update, snapshot, unsupported };
        standard: Standard,
        failure: Failure = .create,
        creates: usize = 0,
        destroys: usize = 0,

        fn owner(context: *anyopaque) *Self {
            const implementation: *Standard = @ptrCast(@alignCast(context));
            return @fieldParentPtr("standard", implementation);
        }

        fn capabilities(context: *anyopaque) p.Capabilities {
            var caps = owner(context).standard.provider().vtable.capabilities(context);
            if (owner(context).failure == .unsupported) caps.setHash(.sha256, false);
            return caps;
        }

        fn create(context: *anyopaque, allocator: std.mem.Allocator, algorithm: p.HashAlgorithm, out: *?*anyopaque) p.ProviderError!void {
            const self = owner(context);
            self.creates += 1;
            if (self.failure == .create) return error.InternalError;
            return self.standard.provider().vtable.hashCreate(context, allocator, algorithm, out);
        }

        fn update(context: *anyopaque, handle: *anyopaque, bytes: []const u8) p.ProviderError!void {
            const self = owner(context);
            if (self.failure == .update) return error.InternalError;
            return self.standard.provider().vtable.hashUpdate(context, handle, bytes);
        }

        fn snapshot(context: *anyopaque, handle: *anyopaque, out: []u8) p.ProviderError!void {
            const self = owner(context);
            if (self.failure == .snapshot) return error.InternalError;
            return self.standard.provider().vtable.hashSnapshot(context, handle, out);
        }

        fn destroy(context: *anyopaque, allocator: std.mem.Allocator, handle: *anyopaque) void {
            const self = owner(context);
            self.destroys += 1;
            self.standard.provider().vtable.hashDestroy(context, allocator, handle);
        }
    };
    var observed: Observed = .{ .standard = .init(testing.io, testing.allocator) };
    var provider = observed.standard.provider();
    var vtable = provider.vtable.*;
    vtable.capabilities = Observed.capabilities;
    vtable.hashCreate = Observed.create;
    vtable.hashUpdate = Observed.update;
    vtable.hashSnapshot = Observed.snapshot;
    vtable.hashDestroy = Observed.destroy;
    provider.vtable = &vtable;
    const adapter = CryptoCertificateVerifier.init(provider);
    for (std.enums.values(Observed.Failure)) |failure| {
        observed.failure = failure;
        observed.creates = 0;
        observed.destroys = 0;
        var out: [32]u8 = @splat(0xa5);
        const expected = if (failure == .unsupported) error.UnsupportedAlgorithm else error.InternalError;
        try testing.expectError(expected, adapter.digestMetadata(testing.allocator, .sha256, "abc", &out, .{}));
        try testing.expectEqual(@as(usize, if (failure == .unsupported) 0 else 1), observed.creates);
        try testing.expectEqual(@as(usize, if (failure == .update or failure == .snapshot) 1 else 0), observed.destroys);
        try testing.expect(std.mem.allEqual(u8, &out, 0));
    }
}

test "certificate metadata digest shares immutable provider without sharing hash state" {
    const testing = std.testing;
    const Shared = struct {
        adapter: *const CryptoCertificateVerifier,
        failed: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            const expected = "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad";
            for (0..64) |_| {
                var out: [32]u8 = undefined;
                self.adapter.digestMetadata(testing.allocator, .sha256, "abc", &out, .{}) catch {
                    self.failed.store(true, .monotonic);
                    return;
                };
                if (!std.mem.eql(u8, expected, &out)) self.failed.store(true, .monotonic);
            }
        }
    };
    var standard = @import("crypto/standard.zig").StandardProvider.init(testing.io, testing.allocator);
    const adapter = CryptoCertificateVerifier.init(standard.provider());
    var shared: Shared = .{ .adapter = &adapter };
    var threads: [4]std.Thread = undefined;
    var started: usize = 0;
    errdefer for (threads[0..started]) |thread| thread.join();
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Shared.run, .{&shared});
        started += 1;
    }
    for (threads) |thread| thread.join();
    started = 0;
    try testing.expect(!shared.failed.load(.monotonic));
}
