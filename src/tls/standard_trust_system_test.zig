//! Explicit local-OS qualification, kept out of deterministic fixture tests.
const std = @import("std");
const policy = @import("standard_trust.zig");
const windows = @import("builtin").os.tag == .windows;

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
    var chain = try fixtures.Chain.init(std.testing.allocator, if (windows) .ecdsa_p256 else .ed25519);
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
    var standard = StandardProvider.initWithOptions(std.testing.io, std.testing.allocator, .{
        .allow_md5_identifier_hash = windows,
    });
    var adapter = CryptoCertificateVerifier.init(standard.provider());
    var binding = try owner.bind(&adapter, .{ .allow_sha1_identifiers = true, .allow_md5_identifiers = windows });
    try binding.provider().verifyPeer(.{
        .role = .server,
        .chain_der = &.{ chain.leaf, chain.intermediate },
        .expected_identity = .{ .dns_name = "api.example.test" },
        .now_seconds = std.Io.Timestamp.now(std.testing.io, .real).toSeconds(),
        .signature_verifier = binding.signatureVerifier(),
        .scratch_allocator = std.testing.allocator,
    });
}

test "Windows Disallowed rejects unavailable Ed25519 metadata while custom-only remains supported" {
    const fixtures = @import("trust_fixtures.zig");
    const StandardProvider = @import("crypto/standard.zig").StandardProvider;
    const CryptoCertificateVerifier = @import("cert_crypto.zig").CryptoCertificateVerifier;
    var chain = try fixtures.Chain.init(std.testing.allocator, .ed25519);
    defer chain.deinit();
    const custom: @import("trust.zig").CaBundleSource = .{ .der_certificates = &.{chain.root} };
    for ([_]bool{ false, true }) |system_restrictions| {
        if (system_restrictions and !windows) continue;
        var owner = try policy.TrustContext.init(std.testing.allocator, std.testing.io, .{
            .source = if (system_restrictions) .{ .system_plus_custom = custom } else .{ .custom_only = custom },
        });
        defer owner.deinit();
        if (system_restrictions) {
            var found = false;
            for (owner.platform_snapshot.?.fingerprint_lists.items) |list|
                found = found or list.identity == .windows_disallowed;
            try std.testing.expect(found);
        } else {
            try std.testing.expect(owner.platform_snapshot == null);
        }
        var standard = StandardProvider.initWithOptions(std.testing.io, std.testing.allocator, .{ .allow_md5_identifier_hash = true });
        var adapter = CryptoCertificateVerifier.init(standard.provider());
        var binding = try owner.bind(&adapter, .{ .allow_sha1_identifiers = true, .allow_md5_identifiers = true });
        const result = binding.provider().verifyPeer(.{
            .role = .server,
            .chain_der = &.{ chain.leaf, chain.intermediate },
            .expected_identity = .{ .dns_name = "api.example.test" },
            .now_seconds = std.Io.Timestamp.now(std.testing.io, .real).toSeconds(),
            .signature_verifier = binding.signatureVerifier(),
            .scratch_allocator = std.testing.allocator,
        });
        if (system_restrictions)
            try std.testing.expectError(error.TlsTrustStoreLoadFailed, result)
        else
            try result;
    }
}
