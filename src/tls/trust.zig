//! Provider-neutral peer trust contract.
//!
//! `TrustProvider` is a borrowed handle. The object that creates it owns all
//! provider state and must outlive every TLS context, session, and concurrent
//! verification using the handle. Providers are immutable after initialization
//! and safe for concurrent calls. Internal caches are permitted only when their
//! synchronization preserves those guarantees.
//!
//! Verification is synchronous. Peer certificates, identities, signature
//! verifier inputs, and scratch allocations must not be retained after
//! `verifyPeer` returns. Per-handshake parsing belongs in `scratch_allocator`;
//! provider-owned trust anchors belong to the provider owner.

const std = @import("std");
const cert_signature = @import("cert_signature.zig");
const errors = @import("errors.zig");

pub const CertificateSignatureVerifier = cert_signature.CertificateSignatureVerifier;
pub const TrustError = errors.TrustError;

/// Role of the peer whose certificate chain is being authenticated.
pub const PeerRole = enum {
    server,
    client,
};

/// Parsed IP literal used for exact `iPAddress` SAN matching.
pub const IpAddress = union(enum) {
    v4: [4]u8,
    v6: [16]u8,
};

/// Borrowed application identity expected from the peer certificate.
pub const PeerIdentity = union(enum) {
    dns_name: []const u8,
    ip_address: IpAddress,
};

/// Finite work and input bounds for one peer verification.
///
/// Implementations may reject inputs earlier, but must never exceed these
/// caller-selected bounds while parsing or constructing a path.
pub const TrustLimits = struct {
    max_peer_certificates: usize = 16,
    max_certificate_der_bytes: usize = 256 * 1024,
    max_chain_der_bytes: usize = 1024 * 1024,
    max_path_depth: usize = 8,
    max_candidate_attempts: usize = 64,

    pub fn validate(self: TrustLimits) TrustError!void {
        if (self.max_peer_certificates == 0 or
            self.max_certificate_der_bytes == 0 or
            self.max_chain_der_bytes < self.max_certificate_der_bytes or
            self.max_path_depth == 0 or
            self.max_candidate_attempts == 0)
        {
            return error.TlsInvalidTrustConfiguration;
        }
    }
};

/// Borrowed inputs for one peer-verification operation.
///
/// `chain_der[0]` is the leaf. Remaining certificates are unordered
/// intermediate candidates, not a pre-validated path. `expected_identity` is
/// normally required for a server peer and normally absent for a client peer.
/// `now_seconds` is Unix time supplied by the TLS context.
pub const VerifyPeerRequest = struct {
    role: PeerRole,
    chain_der: []const []const u8,
    expected_identity: ?PeerIdentity,
    now_seconds: i64,
    signature_verifier: CertificateSignatureVerifier,
    scratch_allocator: std.mem.Allocator,
    limits: TrustLimits = .{},

    /// Performs provider-independent shape and resource-limit checks.
    pub fn validate(self: VerifyPeerRequest) TrustError!void {
        try self.limits.validate();
        if (self.chain_der.len == 0) return error.TlsMalformedCertificateChain;
        if (self.chain_der.len > self.limits.max_peer_certificates) {
            return error.TlsCertificateChainTooLarge;
        }

        var total_der_bytes: usize = 0;
        for (self.chain_der) |certificate_der| {
            if (certificate_der.len == 0) return error.TlsMalformedCertificate;
            if (certificate_der.len > self.limits.max_certificate_der_bytes) {
                return error.TlsCertificateTooLarge;
            }
            total_der_bytes = std.math.add(usize, total_der_bytes, certificate_der.len) catch
                return error.TlsCertificateChainTooLarge;
            if (total_der_bytes > self.limits.max_chain_der_bytes) {
                return error.TlsCertificateChainTooLarge;
            }
        }
    }
};

/// Borrowed, type-erased peer trust provider.
///
/// There is intentionally no `deinit`: the owner that produced the handle
/// controls provider destruction. Copying this descriptor does not copy or
/// transfer ownership of its context.
pub const TrustProvider = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        verify_peer: *const fn (*anyopaque, VerifyPeerRequest) TrustError!void,
    };

    pub fn verifyPeer(self: TrustProvider, request: VerifyPeerRequest) TrustError!void {
        try request.validate();
        return self.vtable.verify_peer(self.context, request);
    }
};

/// Declarative custom CA material.
///
/// All slices are caller-owned and borrowed until runtime trust-context
/// initialization completes. The runtime owner must copy the file contents or
/// certificate DER that it retains.
pub const CaBundleSource = union(enum) {
    pem_file_path: []const u8,
    pem_bytes: []const u8,
    der_certificates: []const []const u8,
};

/// Source used to construct or borrow a runtime trust provider.
///
/// `system_plus_custom` merges private anchors with platform roots;
/// `custom_only` is hermetic and never consults platform roots. A `.provider`
/// handle remains borrowed for the lifetime of every runtime context using it.
pub const TrustSource = union(enum) {
    system,
    system_plus_custom: CaBundleSource,
    custom_only: CaBundleSource,
    provider: TrustProvider,
};

/// Client policy for authenticating a TLS server.
///
/// Secure configurations use `.verify`; the long dangerous tag is the only
/// policy vocabulary for bypassing certificate-chain, identity, and time
/// checks. TLS handshake proof-of-possession remains outside this policy.
pub const ServerAuthentication = union(enum) {
    verify: TrustSource,
    dangerously_insecure_skip_certificate_verification,
};

test "trust provider dispatches borrowed ownership and server identity" {
    const FakeSignatureVerifier = struct {
        fn verify(
            _: *anyopaque,
            _: cert_signature.VerifyCertificateSignatureRequest,
        ) cert_signature.CertificateSignatureError!void {}
    };
    const FakeTrustProvider = struct {
        calls: usize = 0,
        outer_chain_ptr: usize = 0,
        leaf_ptr: usize = 0,
        identity_ptr: usize = 0,
        signature_context_ptr: usize = 0,
        role: ?PeerRole = null,
        now_seconds: i64 = 0,

        fn verifyPeer(context: *anyopaque, request: VerifyPeerRequest) TrustError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            self.outer_chain_ptr = @intFromPtr(request.chain_der.ptr);
            self.leaf_ptr = @intFromPtr(request.chain_der[0].ptr);
            self.identity_ptr = @intFromPtr(request.expected_identity.?.dns_name.ptr);
            self.signature_context_ptr = @intFromPtr(request.signature_verifier.context);
            self.role = request.role;
            self.now_seconds = request.now_seconds;
        }
    };

    var signature_context: u8 = 0;
    const signature_verifier = CertificateSignatureVerifier{
        .context = &signature_context,
        .vtable = &.{ .verify = FakeSignatureVerifier.verify },
    };
    var fake = FakeTrustProvider{};
    const provider = TrustProvider{
        .context = &fake,
        .vtable = &.{ .verify_peer = FakeTrustProvider.verifyPeer },
    };
    const leaf = [_]u8{ 0x30, 0x01, 0x00 };
    const intermediate = [_]u8{ 0x30, 0x01, 0x01 };
    const chain = [_][]const u8{ &leaf, &intermediate };
    const dns_name = "api.example.com";

    try provider.verifyPeer(.{
        .role = .server,
        .chain_der = &chain,
        .expected_identity = .{ .dns_name = dns_name },
        .now_seconds = 1_800_000_000,
        .signature_verifier = signature_verifier,
        .scratch_allocator = std.testing.allocator,
    });

    try std.testing.expectEqual(@as(usize, 1), fake.calls);
    try std.testing.expectEqual(@intFromPtr(chain[0..].ptr), fake.outer_chain_ptr);
    try std.testing.expectEqual(@intFromPtr(leaf[0..].ptr), fake.leaf_ptr);
    try std.testing.expectEqual(@intFromPtr(dns_name.ptr), fake.identity_ptr);
    try std.testing.expectEqual(@intFromPtr(&signature_context), fake.signature_context_ptr);
    try std.testing.expectEqual(PeerRole.server, fake.role.?);
    try std.testing.expectEqual(@as(i64, 1_800_000_000), fake.now_seconds);
}

test "trust request carries client role IP identity and strict limits" {
    const FakeSignatureVerifier = struct {
        fn verify(
            _: *anyopaque,
            _: cert_signature.VerifyCertificateSignatureRequest,
        ) cert_signature.CertificateSignatureError!void {}
    };
    const FakeTrustProvider = struct {
        calls: usize = 0,
        role: ?PeerRole = null,
        ip_address: ?[4]u8 = null,
        max_peer_certificates: usize = 0,
        max_path_depth: usize = 0,
        max_candidate_attempts: usize = 0,

        fn verifyPeer(context: *anyopaque, request: VerifyPeerRequest) TrustError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            self.role = request.role;
            self.ip_address = request.expected_identity.?.ip_address.v4;
            self.max_peer_certificates = request.limits.max_peer_certificates;
            self.max_path_depth = request.limits.max_path_depth;
            self.max_candidate_attempts = request.limits.max_candidate_attempts;
        }
    };

    var signature_context: u8 = 0;
    const signature_verifier = CertificateSignatureVerifier{
        .context = &signature_context,
        .vtable = &.{ .verify = FakeSignatureVerifier.verify },
    };
    var fake = FakeTrustProvider{};
    const provider = TrustProvider{
        .context = &fake,
        .vtable = &.{ .verify_peer = FakeTrustProvider.verifyPeer },
    };
    const leaf = [_]u8{0x30};
    const chain = [_][]const u8{&leaf};

    try provider.verifyPeer(.{
        .role = .client,
        .chain_der = &chain,
        .expected_identity = .{ .ip_address = .{ .v4 = .{ 127, 0, 0, 1 } } },
        .now_seconds = 0,
        .signature_verifier = signature_verifier,
        .scratch_allocator = std.testing.allocator,
        .limits = .{
            .max_peer_certificates = 3,
            .max_certificate_der_bytes = 32,
            .max_chain_der_bytes = 64,
            .max_path_depth = 2,
            .max_candidate_attempts = 7,
        },
    });
    try std.testing.expectEqual(@as(usize, 1), fake.calls);
    try std.testing.expectEqual(PeerRole.client, fake.role.?);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, fake.ip_address.?);
    try std.testing.expectEqual(@as(usize, 3), fake.max_peer_certificates);
    try std.testing.expectEqual(@as(usize, 2), fake.max_path_depth);
    try std.testing.expectEqual(@as(usize, 7), fake.max_candidate_attempts);
}

test "trust provider preserves specific errors" {
    const FakeSignatureVerifier = struct {
        fn verify(
            _: *anyopaque,
            _: cert_signature.VerifyCertificateSignatureRequest,
        ) cert_signature.CertificateSignatureError!void {}
    };
    const FakeTrustProvider = struct {
        fn verifyPeer(_: *anyopaque, _: VerifyPeerRequest) TrustError!void {
            return error.TlsUnknownCa;
        }
    };

    var context: u8 = 0;
    const signature_verifier = CertificateSignatureVerifier{
        .context = &context,
        .vtable = &.{ .verify = FakeSignatureVerifier.verify },
    };
    const provider = TrustProvider{
        .context = &context,
        .vtable = &.{ .verify_peer = FakeTrustProvider.verifyPeer },
    };
    const leaf = [_]u8{0x30};
    const chain = [_][]const u8{&leaf};

    try std.testing.expectError(error.TlsUnknownCa, provider.verifyPeer(.{
        .role = .server,
        .chain_der = &chain,
        .expected_identity = .{ .dns_name = "example.com" },
        .now_seconds = 0,
        .signature_verifier = signature_verifier,
        .scratch_allocator = std.testing.allocator,
    }));
}

test "trust request enforces finite certificate limits before dispatch" {
    const FakeSignatureVerifier = struct {
        fn verify(
            _: *anyopaque,
            _: cert_signature.VerifyCertificateSignatureRequest,
        ) cert_signature.CertificateSignatureError!void {}
    };
    const FakeTrustProvider = struct {
        calls: usize = 0,

        fn verifyPeer(context: *anyopaque, _: VerifyPeerRequest) TrustError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
        }
    };

    var fake = FakeTrustProvider{};
    const signature_verifier = CertificateSignatureVerifier{
        .context = &fake,
        .vtable = &.{ .verify = FakeSignatureVerifier.verify },
    };
    const provider = TrustProvider{
        .context = &fake,
        .vtable = &.{ .verify_peer = FakeTrustProvider.verifyPeer },
    };
    const oversized = [_]u8{ 0x30, 0x01 };
    const chain = [_][]const u8{&oversized};

    try std.testing.expectError(error.TlsCertificateTooLarge, provider.verifyPeer(.{
        .role = .server,
        .chain_der = &chain,
        .expected_identity = null,
        .now_seconds = 0,
        .signature_verifier = signature_verifier,
        .scratch_allocator = std.testing.allocator,
        .limits = .{
            .max_peer_certificates = 1,
            .max_certificate_der_bytes = 1,
            .max_chain_der_bytes = 1,
            .max_path_depth = 1,
            .max_candidate_attempts = 1,
        },
    }));
    try std.testing.expectEqual(@as(usize, 0), fake.calls);

    var invalid_limits = TrustLimits{};
    invalid_limits.max_candidate_attempts = 0;
    try std.testing.expectError(error.TlsInvalidTrustConfiguration, invalid_limits.validate());
}

test "trust sources and server authentication remain declarative" {
    const custom_der = [_]u8{ 0x30, 0x01, 0x00 };
    const certificates = [_][]const u8{&custom_der};
    const source: TrustSource = .{
        .system_plus_custom = .{ .der_certificates = &certificates },
    };
    const policy: ServerAuthentication = .{ .verify = source };

    try std.testing.expectEqual(@as(usize, 1), policy.verify.system_plus_custom.der_certificates.len);
    try std.testing.expectEqual(
        @intFromPtr(custom_der[0..].ptr),
        @intFromPtr(policy.verify.system_plus_custom.der_certificates[0].ptr),
    );

    const secure_default: ServerAuthentication = .{ .verify = .system };
    try std.testing.expect(secure_default == .verify);
    const dangerous: ServerAuthentication = .dangerously_insecure_skip_certificate_verification;
    try std.testing.expect(dangerous == .dangerously_insecure_skip_certificate_verification);
}
