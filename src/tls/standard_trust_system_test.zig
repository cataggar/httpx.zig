//! Explicit local-OS qualification, kept out of deterministic fixture tests.
const std = @import("std");
const policy = @import("standard_trust.zig");

test "supported native-free system stores supply bounded usable roots" {
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
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    try owner.provider().verifyPeer(.{
        .role = .server,
        .chain_der = &.{ chain.leaf, chain.intermediate },
        .expected_identity = .{ .dns_name = "api.example.test" },
        .now_seconds = 1_800_000_000,
        .signature_verifier = verifier.verifier(),
        .scratch_allocator = std.testing.allocator,
    });
}
