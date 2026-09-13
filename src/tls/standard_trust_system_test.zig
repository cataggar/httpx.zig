//! Explicit local-OS qualification, kept out of deterministic fixture tests.
const std = @import("std");
const policy = @import("standard_trust.zig");

test "supported read-only system stores supply bounded anchor candidates" {
    if (!policy.supportsSystemRoots()) {
        try std.testing.expectError(error.TlsTrustStoreLoadFailed, policy.TrustContext.init(
            std.testing.allocator,
            std.testing.io,
            .{},
        ));
        return;
    }
    var owner = try policy.TrustContext.init(std.testing.allocator, std.testing.io, .{});
    defer owner.deinit();
    try std.testing.expect(owner.anchorCount() > 0);
    std.debug.print("system trust snapshot: {d} anchors, {d} outside profile\n", .{
        owner.anchorCount(), owner.skipped_system_anchors,
    });
}

test "system discovery respects its peak allocation budget" {
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, policy.TrustContext.init(
        std.testing.allocator,
        std.testing.io,
        .{ .max_system_load_bytes = 1 },
    ));
}

test "system plus custom authenticates a private local chain without replacing system trust" {
    const fixtures = @import("trust_fixtures.zig");
    const StandardProvider = @import("crypto/standard.zig").StandardProvider;
    const CryptoCertificateVerifier = @import("cert_crypto.zig").CryptoCertificateVerifier;
    var chain = try fixtures.Chain.init(std.testing.allocator, .ed25519);
    defer chain.deinit();
    const options: policy.Options = .{
        .source = .{ .system_plus_custom = .{ .der_certificates = &.{chain.root} } },
    };
    if (!policy.supportsSystemRoots()) {
        try std.testing.expectError(error.TlsTrustStoreLoadFailed, policy.TrustContext.init(std.testing.allocator, std.testing.io, options));
        return;
    }
    var owner = try policy.TrustContext.init(std.testing.allocator, std.testing.io, options);
    defer owner.deinit();
    try std.testing.expect(owner.anchorCount() > 1);
    var standard = StandardProvider.init(std.testing.io, std.testing.allocator);
    const p = @import("crypto/provider.zig");
    const signature = @import("cert_signature.zig");
    const digest = @import("metadata_digest.zig");
    // Direct policy conformance only; production runtime adapter wiring is
    // qualified separately. Both facets use this one selected provider.
    const Adapter = struct {
        selected: p.CryptoProvider,
        pub fn verifier(self: *@This()) signature.CertificateSignatureVerifier {
            return .{ .context = self, .vtable = &.{ .verify = verify } };
        }
        pub fn metadataHasher(self: *@This(), options_value: digest.Options) digest.MetadataDigest {
            return .{ .context = self, .digest_fn = hash, .options = options_value };
        }
        fn verify(context: *anyopaque, request: signature.VerifyCertificateSignatureRequest) signature.CertificateSignatureError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            var bridge = CryptoCertificateVerifier.init(self.selected);
            try bridge.verifier().verify(request);
        }
        fn hash(context: *anyopaque, allocator: std.mem.Allocator, algorithm: p.HashAlgorithm, bytes: []const u8, output: []u8) p.ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            errdefer @memset(output, 0);
            var handle = try self.selected.hashCreate(allocator, algorithm);
            defer handle.deinit();
            try handle.update(bytes);
            try handle.snapshot(output);
        }
    };
    var adapter = Adapter{ .selected = standard.provider() };
    var binding = try owner.bind(&adapter, .{ .allow_sha1_identifiers = true });
    try binding.provider().verifyPeer(.{
        .role = .server,
        .chain_der = &.{ chain.leaf, chain.intermediate },
        .expected_identity = .{ .dns_name = "api.example.test" },
        .now_seconds = std.Io.Timestamp.now(std.testing.io, .real).toSeconds(),
        .signature_verifier = binding.signatureVerifier(),
        .scratch_allocator = std.testing.allocator,
    });
}
