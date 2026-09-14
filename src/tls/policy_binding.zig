//! ABI-v1 policy view pairing signature verification with identifier hashing.
//! Construct both handles from one selected-provider adapter. This view owns
//! neither that adapter/provider nor the immutable roots. All must outlive
//! pooled TLS sessions and active calls; keep this view at a stable address
//! after provider(). Each call supplies its own concurrency-safe scratch.
//! Do not retarget/mutate the binding or adapter/provider configuration while
//! borrowed views are in use.
const std = @import("std");
const trust = @import("trust.zig");
const metadata = @import("metadata_digest.zig");
const Error = trust.TrustError;

pub const PolicyBinding = struct {
    roots_context: *const anyopaque,
    verify_policy: *const fn (*const anyopaque, trust.VerifyPeerRequest, metadata.MetadataDigest) Error!void,
    signature_verifier: trust.CertificateSignatureVerifier,
    metadata_digest: metadata.MetadataDigest,

    /// The canonical root owner supplies its private policy callback; its
    /// factory obtains both handles from the same selected-provider adapter.
    pub fn init(
        roots_context: *const anyopaque,
        verify_policy: *const fn (*const anyopaque, trust.VerifyPeerRequest, metadata.MetadataDigest) Error!void,
        signature_verifier: trust.CertificateSignatureVerifier,
        metadata_digest: metadata.MetadataDigest,
    ) Error!PolicyBinding {
        if (signature_verifier.context != metadata_digest.context)
            return error.TlsInvalidTrustConfiguration;
        return .{
            .roots_context = roots_context,
            .verify_policy = verify_policy,
            .signature_verifier = signature_verifier,
            .metadata_digest = metadata_digest,
        };
    }

    /// Runtime requests must carry this exact handle, not a new transient
    /// adapter or a signature verifier selected independently from the hash.
    pub fn signatureVerifier(self: *const PolicyBinding) trust.CertificateSignatureVerifier {
        return self.signature_verifier;
    }

    pub fn provider(self: *PolicyBinding) trust.TrustProvider {
        return .{ .context = self, .vtable = &.{ .verify_peer = verifyPeer } };
    }

    fn verifyPeer(context: *anyopaque, request: trust.VerifyPeerRequest) Error!void {
        const self: *const PolicyBinding = @ptrCast(@alignCast(context));
        try request.validate();
        if (request.signature_verifier.context != self.signature_verifier.context or
            request.signature_verifier.vtable != self.signature_verifier.vtable or
            self.metadata_digest.context != self.signature_verifier.context)
            return error.TlsInvalidTrustConfiguration;
        try self.verify_policy(self.roots_context, request, self.metadata_digest);
    }
};

test "policy binding pairs dispatch and rejects mismatched signature or digest handles" {
    const crypto = @import("crypto/provider.zig");
    const signature = @import("cert_signature.zig");
    const Adapter = struct {
        signatures: usize = 0,
        hashes: usize = 0,
        fn verify(context: *anyopaque, _: signature.VerifyCertificateSignatureRequest) signature.CertificateSignatureError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.signatures += 1;
        }
        fn wrongVerify(_: *anyopaque, _: signature.VerifyCertificateSignatureRequest) signature.CertificateSignatureError!void {
            return error.InvalidSignature;
        }
        fn digest(context: *anyopaque, _: std.mem.Allocator, _: crypto.HashAlgorithm, _: []const u8, output: []u8) crypto.ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.hashes += 1;
            @memset(output, 0x42);
        }
        fn verifier(self: *@This()) trust.CertificateSignatureVerifier {
            return .{ .context = self, .vtable = &.{ .verify = verify } };
        }
    };
    const Roots = struct {
        fn verify(_: *const anyopaque, request: trust.VerifyPeerRequest, hasher: metadata.MetadataDigest) Error!void {
            var output: [32]u8 = undefined;
            hasher.hash(request.scratch_allocator, .sha256, request.chain_der[0], &output) catch
                return error.TlsCertificateConstraintViolation;
            request.signature_verifier.verify(.{
                .algorithm = .{ .oid = "\x2b\x65\x70" },
                .issuer_spki_der = "fixture key",
                .tbs_certificate_der = request.chain_der[0],
                .signature = "fixture signature",
            }) catch return error.TlsCertificateSignatureInvalid;
        }
    };
    var selected = Adapter{};
    var other = Adapter{};
    const hasher = metadata.MetadataDigest{ .context = &selected, .digest_fn = Adapter.digest };
    const roots: u8 = 0;
    try std.testing.expectError(error.TlsInvalidTrustConfiguration, PolicyBinding.init(&roots, Roots.verify, other.verifier(), hasher));
    var binding = try PolicyBinding.init(&roots, Roots.verify, selected.verifier(), hasher);
    var request = trust.VerifyPeerRequest{
        .role = .server,
        .chain_der = &.{"fixture DER"},
        .expected_identity = .{ .dns_name = "api.example.test" },
        .now_seconds = 1_800_000_000,
        .signature_verifier = binding.signatureVerifier(),
        .scratch_allocator = std.testing.allocator,
    };
    try binding.provider().verifyPeer(request);
    try std.testing.expectEqual(@as(usize, 1), selected.signatures);
    try std.testing.expectEqual(@as(usize, 1), selected.hashes);
    request.signature_verifier = other.verifier();
    try std.testing.expectError(error.TlsInvalidTrustConfiguration, binding.provider().verifyPeer(request));
    request.signature_verifier = .{ .context = &selected, .vtable = &.{ .verify = Adapter.wrongVerify } };
    try std.testing.expectError(error.TlsInvalidTrustConfiguration, binding.provider().verifyPeer(request));
    try std.testing.expectEqual(@as(usize, 1), selected.signatures);
    try std.testing.expectEqual(@as(usize, 1), selected.hashes);
    try std.testing.expectEqual(@as(usize, 0), other.signatures);
    try std.testing.expectEqual(@as(usize, 0), other.hashes);
}

test "policy binding leaves existing ABI-v1 request and vtables unchanged" {
    try std.testing.expectEqual(@as(usize, 1), @typeInfo(trust.TrustProvider.VTable).@"struct".fields.len);
    try std.testing.expectEqual(@as(usize, 1), @typeInfo(trust.CertificateSignatureVerifier.VTable).@"struct".fields.len);
    const fields = @typeInfo(trust.VerifyPeerRequest).@"struct".fields;
    try std.testing.expectEqual(@as(usize, 7), fields.len);
    try std.testing.expectEqualStrings("signature_verifier", fields[4].name);
}
