//! Provider-neutral certificate-signature verification contract.
//!
//! This module deliberately exposes only the data needed to authenticate an
//! X.509 certificate edge. It does not expose TLS transcripts, random-number
//! generation, key exchange, AEAD, or handshake CertificateVerify policy.

/// Borrowed DER components of an X.509 `AlgorithmIdentifier`.
pub const AlgorithmIdentifier = struct {
    /// DER OBJECT IDENTIFIER content octets, excluding the tag and length.
    oid: []const u8,
    /// Complete DER element for the parameters, or `null` when absent.
    parameters_der: ?[]const u8 = null,
};

/// Inputs for one certificate-signature verification.
///
/// Every slice is borrowed and remains valid only for the synchronous
/// `CertificateSignatureVerifier.verify` call. The signature contains the
/// BIT STRING payload, excluding its unused-bits count octet.
pub const VerifyCertificateSignatureRequest = struct {
    algorithm: AlgorithmIdentifier,
    issuer_spki_der: []const u8,
    tbs_certificate_der: []const u8,
    signature: []const u8,
};

/// Provider-neutral failures from the certificate-signature bridge.
///
/// A trust implementation maps these errors to its public trust categories.
pub const CertificateSignatureError = error{
    UnsupportedAlgorithm,
    MalformedAlgorithmIdentifier,
    MalformedSubjectPublicKeyInfo,
    InvalidSignature,
    OutOfMemory,
};

/// Borrowed, type-erased certificate-signature verifier.
///
/// The owner of `context` and `vtable` must outlive every copy of this handle
/// and every call through it. Copying the handle does not transfer ownership.
/// Callbacks are synchronous and must not retain request slices. A verifier
/// shared by concurrent trust operations must be thread-safe.
pub const CertificateSignatureVerifier = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        verify: *const fn (*anyopaque, VerifyCertificateSignatureRequest) CertificateSignatureError!void,
    };

    pub fn verify(
        self: CertificateSignatureVerifier,
        request: VerifyCertificateSignatureRequest,
    ) CertificateSignatureError!void {
        return self.vtable.verify(self.context, request);
    }
};

test "certificate signature verifier dispatches borrowed inputs" {
    const std = @import("std");

    const FakeVerifier = struct {
        calls: usize = 0,
        oid_ptr: usize = 0,
        parameters_ptr: usize = 0,
        spki_ptr: usize = 0,
        tbs_ptr: usize = 0,
        signature_ptr: usize = 0,

        fn verify(
            context: *anyopaque,
            request: VerifyCertificateSignatureRequest,
        ) CertificateSignatureError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            self.oid_ptr = @intFromPtr(request.algorithm.oid.ptr);
            self.parameters_ptr = @intFromPtr(request.algorithm.parameters_der.?.ptr);
            self.spki_ptr = @intFromPtr(request.issuer_spki_der.ptr);
            self.tbs_ptr = @intFromPtr(request.tbs_certificate_der.ptr);
            self.signature_ptr = @intFromPtr(request.signature.ptr);
        }
    };

    var fake = FakeVerifier{};
    const verifier = CertificateSignatureVerifier{
        .context = &fake,
        .vtable = &.{ .verify = FakeVerifier.verify },
    };
    const oid = [_]u8{ 0x2a, 0x86, 0x48 };
    const parameters = [_]u8{ 0x05, 0x00 };
    const spki = [_]u8{ 0x30, 0x01, 0x00 };
    const tbs = [_]u8{ 0x30, 0x02, 0x01, 0x01 };
    const signature = [_]u8{ 0xaa, 0xbb };

    try verifier.verify(.{
        .algorithm = .{ .oid = &oid, .parameters_der = &parameters },
        .issuer_spki_der = &spki,
        .tbs_certificate_der = &tbs,
        .signature = &signature,
    });

    try std.testing.expectEqual(@as(usize, 1), fake.calls);
    try std.testing.expectEqual(@intFromPtr(oid[0..].ptr), fake.oid_ptr);
    try std.testing.expectEqual(@intFromPtr(parameters[0..].ptr), fake.parameters_ptr);
    try std.testing.expectEqual(@intFromPtr(spki[0..].ptr), fake.spki_ptr);
    try std.testing.expectEqual(@intFromPtr(tbs[0..].ptr), fake.tbs_ptr);
    try std.testing.expectEqual(@intFromPtr(signature[0..].ptr), fake.signature_ptr);
}

test "certificate signature verifier preserves provider errors" {
    const std = @import("std");

    const FakeVerifier = struct {
        fn verify(
            _: *anyopaque,
            _: VerifyCertificateSignatureRequest,
        ) CertificateSignatureError!void {
            return error.UnsupportedAlgorithm;
        }
    };

    var context: u8 = 0;
    const verifier = CertificateSignatureVerifier{
        .context = &context,
        .vtable = &.{ .verify = FakeVerifier.verify },
    };

    try std.testing.expectError(error.UnsupportedAlgorithm, verifier.verify(.{
        .algorithm = .{ .oid = &.{} },
        .issuer_spki_der = &.{},
        .tbs_certificate_der = &.{},
        .signature = &.{},
    }));
}
