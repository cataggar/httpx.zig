//! Adapts certificate signatures to a selected CryptoProvider. Trust, name,
//! validity, usage and path-constraint decisions remain with TrustProvider.
const std = @import("std");
const signature = @import("cert_signature.zig");
const p = @import("crypto/provider.zig");
const der = @import("crypto/der.zig");
const Error = signature.CertificateSignatureError;
const Certificate = std.crypto.Certificate;

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

    fn verify(context: *anyopaque, request: signature.VerifyCertificateSignatureRequest) Error!void {
        const self: *const CryptoCertificateVerifier = @ptrCast(@alignCast(context));
        const scheme = try signatureScheme(request.algorithm);
        const key = try publicKey(request.issuer_spki_der);
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
    const id = Certificate.Algorithm.map.get(algorithm.oid) orelse return error.UnsupportedAlgorithm;
    switch (id) {
        .sha1WithRSAEncryption, .sha256WithRSAEncryption, .sha384WithRSAEncryption, .sha512WithRSAEncryption => {
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
        .sha1WithRSAEncryption => .rsa_pkcs1_sha1,
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

fn parsePublicKey(bytes: []const u8) (der.Error || error{UnsupportedAlgorithm})!p.PublicKey {
    if (bytes.len > 4096) return error.InvalidEncoding;
    var spki = try der.sequence(bytes);
    var algorithm: der.Reader = .{ .bytes = try spki.take(0x30) };
    const oid = try algorithm.take(0x06);
    const bits = try spki.take(0x03);
    try spki.finish();
    if (bits.len < 2 or bits[0] != 0) return error.InvalidEncoding;
    const id = Certificate.AlgorithmCategory.map.get(oid) orelse return error.UnsupportedAlgorithm;
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
        // Restricted PSS keys require enforcing their AlgorithmIdentifier
        // restrictions, which the primitive PublicKey contract does not carry.
        .rsassa_pss => return error.UnsupportedAlgorithm,
    };
    try algorithm.finish();
    return key;
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
