const std = @import("std");
const trust = @import("trust.zig");
const policy = @import("standard_trust.zig");
const x509 = @import("x509_policy.zig");
const fixtures = @import("trust_fixtures.zig");
const StandardProvider = @import("crypto/standard.zig").StandardProvider;
const CryptoCertificateVerifier = @import("cert_crypto.zig").CryptoCertificateVerifier;
const primitives = @import("crypto/provider.zig");
const testing = std.testing;
const now_seconds = 1_800_000_000;

fn request(chain: []const []const u8, verifier: trust.CertificateSignatureVerifier) trust.VerifyPeerRequest {
    return .{
        .role = .server,
        .chain_der = chain,
        .expected_identity = .{ .dns_name = "api.example.test" },
        .now_seconds = now_seconds,
        .signature_verifier = verifier,
        .scratch_allocator = testing.allocator,
    };
}

fn context(root: []const u8) !policy.TrustContext {
    return policy.TrustContext.init(testing.allocator, testing.io, .{
        .source = .{ .custom_only = .{ .der_certificates = &.{root} } },
    });
}

test "local Ed25519 and P256 chains require explicit roots and accept unordered intermediates" {
    inline for (std.meta.tags(fixtures.Scheme)) |scheme| {
        var chain = try fixtures.Chain.init(testing.allocator, scheme);
        defer chain.deinit();
        var owner = try context(chain.root);
        defer owner.deinit();
        try testing.expectEqual(@as(usize, 1), owner.anchorCount());
        var standard = StandardProvider.init(testing.io, testing.allocator);
        var verifier = CryptoCertificateVerifier.init(standard.provider());
        try owner.provider().verifyPeer(request(&.{ chain.leaf, chain.intermediate }, verifier.verifier()));
        try owner.provider().verifyPeer(request(&.{ chain.leaf, chain.root, chain.intermediate }, verifier.verifier()));
        try testing.expectError(error.TlsUnknownCa, owner.provider().verifyPeer(request(&.{chain.leaf}, verifier.verifier())));
        var explicit_intermediate = try context(chain.intermediate);
        defer explicit_intermediate.deinit();
        try explicit_intermediate.provider().verifyPeer(request(&.{chain.leaf}, verifier.verifier()));

        const other_key = try fixtures.Key.init(scheme, 9);
        var other_options = fixtures.rootOptions();
        other_options.subject = "Unknown Root";
        other_options.issuer = "Unknown Root";
        const unknown_root = try fixtures.certificate(testing.allocator, other_key, other_key, other_options);
        defer testing.allocator.free(unknown_root);
        var unknown = try context(unknown_root);
        defer unknown.deinit();
        try testing.expectError(error.TlsUnknownCa, unknown.provider().verifyPeer(request(&.{
            chain.leaf, chain.intermediate, chain.root,
        }, verifier.verifier())));
        try testing.expectError(error.TlsCertificateUsageInvalid, context(chain.leaf));
    }
}

test "path builder backtracks from same-name wrong-key issuers" {
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    const wrong_key = try fixtures.Key.init(.ed25519, 8);
    const wrong_intermediate = try fixtures.certificate(testing.allocator, wrong_key, chain.root_key, fixtures.intermediateOptions());
    defer testing.allocator.free(wrong_intermediate);
    var owner = try context(chain.root);
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    try owner.provider().verifyPeer(request(&.{
        chain.leaf, wrong_intermediate, chain.intermediate,
    }, verifier.verifier()));
    try testing.expectError(error.TlsCertificateSignatureInvalid, owner.provider().verifyPeer(request(&.{
        chain.leaf, wrong_intermediate,
    }, verifier.verifier())));
}

test "CA basic constraints path length key usage and intermediate EKU are enforced" {
    const Case = enum { not_ca, missing_basic, no_key_cert_sign, wrong_eku, expired, future, unknown_critical, name_constraints };
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    var owner = try context(chain.root);
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    inline for (std.meta.tags(Case)) |case| {
        var options = fixtures.intermediateOptions();
        const expected = switch (case) {
            .not_ca => blk: {
                options.is_ca = false;
                options.path_length = null;
                break :blk error.TlsCertificateUsageInvalid;
            },
            .missing_basic => blk: {
                options.omit_basic_constraints = true;
                break :blk error.TlsCertificateUsageInvalid;
            },
            .no_key_cert_sign => blk: {
                options.key_usage = "\x07\x80";
                break :blk error.TlsCertificateUsageInvalid;
            },
            .wrong_eku => blk: {
                options.eku = .client;
                break :blk error.TlsCertificateUsageInvalid;
            },
            .expired => blk: {
                options.not_after = "260101000000Z";
                break :blk error.TlsCertificateExpired;
            },
            .future => blk: {
                options.not_before = "340101000000Z";
                break :blk error.TlsCertificateNotYetValid;
            },
            .unknown_critical => blk: {
                options.extra_extensions = &.{.{ .oid = "\x55\x1d\x7f", .value = "\x05\x00", .critical = true }};
                break :blk error.TlsCertificateConstraintViolation;
            },
            .name_constraints => blk: {
                options.extra_extensions = &.{.{ .oid = "\x55\x1d\x1e", .value = "\x30\x00" }};
                break :blk error.TlsCertificateConstraintViolation;
            },
        };
        const intermediate = try fixtures.certificate(testing.allocator, chain.intermediate_key, chain.root_key, options);
        defer testing.allocator.free(intermediate);
        try testing.expectError(expected, owner.provider().verifyPeer(request(&.{ chain.leaf, intermediate }, verifier.verifier())));
    }
    var root_options = fixtures.rootOptions();
    root_options.path_length = 0;
    const root = try fixtures.certificate(testing.allocator, chain.root_key, chain.root_key, root_options);
    defer testing.allocator.free(root);
    var constrained = try context(root);
    defer constrained.deinit();
    try testing.expectError(error.TlsCertificateConstraintViolation, constrained.provider().verifyPeer(request(&.{
        chain.leaf, chain.intermediate,
    }, verifier.verifier())));
}

test "leaf validity purpose signature and unsupported critical policy fail closed" {
    const Case = enum { expired, future, no_digital_signature, wrong_eku, unknown_critical, duplicate_basic, bad_date, weak_signature };
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    var owner = try context(chain.root);
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    inline for (std.meta.tags(Case)) |case| {
        var options = fixtures.leafOptions();
        const expected = switch (case) {
            .expired => blk: {
                options.not_after = "260101000000Z";
                break :blk error.TlsCertificateExpired;
            },
            .future => blk: {
                options.not_before = "340101000000Z";
                break :blk error.TlsCertificateNotYetValid;
            },
            .no_digital_signature => blk: {
                options.key_usage = "\x05\x20";
                break :blk error.TlsCertificateUsageInvalid;
            },
            .wrong_eku => blk: {
                options.eku = .client;
                break :blk error.TlsCertificateUsageInvalid;
            },
            .unknown_critical => blk: {
                options.extra_extensions = &.{.{ .oid = "\x55\x1d\x7f", .value = "\x05\x00", .critical = true }};
                break :blk error.TlsCertificateConstraintViolation;
            },
            .duplicate_basic => blk: {
                options.extra_extensions = &.{.{ .oid = "\x55\x1d\x13", .value = "\x30\x00" }};
                break :blk error.TlsMalformedCertificate;
            },
            .bad_date => blk: {
                options.not_after = "351301000000Z";
                break :blk error.TlsMalformedCertificate;
            },
            .weak_signature => blk: {
                options.signature_algorithm_override = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05\x05\x00";
                break :blk error.TlsUnsupportedCertificateSignatureAlgorithm;
            },
        };
        const leaf = try fixtures.certificate(testing.allocator, chain.leaf_key, chain.intermediate_key, options);
        defer testing.allocator.free(leaf);
        try testing.expectError(expected, owner.provider().verifyPeer(request(&.{ leaf, chain.intermediate }, verifier.verifier())));
    }
    chain.leaf[chain.leaf.len - 1] ^= 1;
    try testing.expectError(error.TlsCertificateSignatureInvalid, owner.provider().verifyPeer(request(&.{
        chain.leaf, chain.intermediate,
    }, verifier.verifier())));
}

test "leaf SAN DNS wildcard and exact IP policies do not use common name fallback" {
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    var owner = try context(chain.root);
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    var req = request(&.{ chain.leaf, chain.intermediate }, verifier.verifier());
    for ([_][]const u8{ "API.EXAMPLE.TEST.", "one.wild.example.test" }) |dns| {
        req.expected_identity = .{ .dns_name = dns };
        try owner.provider().verifyPeer(req);
    }
    for ([_][]const u8{ "other.example.test", "wild.example.test", "a.b.wild.example.test" }) |dns| {
        req.expected_identity = .{ .dns_name = dns };
        try testing.expectError(error.TlsHostnameMismatch, owner.provider().verifyPeer(req));
    }
    req.expected_identity = .{ .ip_address = .{ .v4 = .{ 127, 0, 0, 1 } } };
    try owner.provider().verifyPeer(req);
    req.expected_identity = .{ .ip_address = .{ .v6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };
    try owner.provider().verifyPeer(req);
    req.expected_identity = .{ .ip_address = .{ .v4 = .{ 127, 0, 0, 2 } } };
    try testing.expectError(error.TlsHostnameMismatch, owner.provider().verifyPeer(req));
    req.expected_identity = .{ .dns_name = "127.0.0.1" };
    try testing.expectError(error.TlsInvalidTrustConfiguration, owner.provider().verifyPeer(req));
    req.expected_identity = null;
    try testing.expectError(error.TlsInvalidTrustConfiguration, owner.provider().verifyPeer(req));

    var options = fixtures.leafOptions();
    options.subject = "api.example.test";
    options.san = null;
    const leaf = try fixtures.certificate(testing.allocator, chain.leaf_key, chain.intermediate_key, options);
    defer testing.allocator.free(leaf);
    try testing.expectError(error.TlsHostnameMismatch, owner.provider().verifyPeer(request(&.{
        leaf, chain.intermediate,
    }, verifier.verifier())));
}

test "client authentication role validates client EKU without requiring a DNS name" {
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    var owner = try context(chain.root);
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    var options = fixtures.leafOptions();
    options.eku = .client;
    options.san = null;
    const leaf = try fixtures.certificate(testing.allocator, chain.leaf_key, chain.intermediate_key, options);
    defer testing.allocator.free(leaf);
    var req = request(&.{ leaf, chain.intermediate }, verifier.verifier());
    req.role = .client;
    req.expected_identity = null;
    try owner.provider().verifyPeer(req);
    req.chain_der = &.{ chain.leaf, chain.intermediate };
    try testing.expectError(error.TlsCertificateUsageInvalid, owner.provider().verifyPeer(req));
}

test "certificate path and input bounds are finite and duplicate peers are rejected" {
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    var owner = try context(chain.root);
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    var req = request(&.{ chain.leaf, chain.intermediate }, verifier.verifier());
    req.limits.max_path_depth = 2;
    try testing.expectError(error.TlsCertificatePathTooDeep, owner.provider().verifyPeer(req));
    req.limits = .{};
    req.limits.max_candidate_attempts = 1;
    try testing.expectError(error.TlsCertificatePathSearchLimitExceeded, owner.provider().verifyPeer(req));
    req.limits = .{};
    req.limits.max_peer_certificates = 1;
    try testing.expectError(error.TlsCertificateChainTooLarge, owner.provider().verifyPeer(req));
    req.limits = .{};
    req.limits.max_certificate_der_bytes = chain.leaf.len - 1;
    try testing.expectError(error.TlsCertificateTooLarge, owner.provider().verifyPeer(req));
    req.limits.max_certificate_der_bytes = @max(chain.leaf.len, chain.intermediate.len);
    req.limits.max_chain_der_bytes = chain.leaf.len + chain.intermediate.len - 1;
    try testing.expectError(error.TlsCertificateChainTooLarge, owner.provider().verifyPeer(req));
    req.limits = .{};
    req.chain_der = &.{ chain.leaf, chain.intermediate, chain.intermediate };
    try testing.expectError(error.TlsMalformedCertificateChain, owner.provider().verifyPeer(req));
}

test "selected primitive rejection cannot fall back to native certificate verification" {
    const Reject = struct {
        calls: usize = 0,
        fail_oom: bool = false,

        fn verify(raw: *anyopaque, _: primitives.SignatureScheme, _: primitives.PublicKey, _: []const []const u8, _: []const u8) primitives.ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.calls += 1;
            return if (self.fail_oom) error.OutOfMemory else error.UnsupportedOperation;
        }
    };
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    var owner = try context(chain.root);
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var reject = Reject{};
    var vtable = standard.provider().vtable.*;
    vtable.verify = Reject.verify;
    var bridge = CryptoCertificateVerifier.init(primitives.CryptoProvider.init(&reject, &vtable));
    const req = request(&.{ chain.leaf, chain.intermediate }, bridge.verifier());
    try testing.expectError(error.TlsUnsupportedCertificateSignatureAlgorithm, owner.provider().verifyPeer(req));
    try testing.expectEqual(@as(usize, 1), reject.calls);
    reject.fail_oom = true;
    try testing.expectError(error.OutOfMemory, owner.provider().verifyPeer(req));
    try testing.expectEqual(@as(usize, 2), reject.calls);
}

fn initializationAndVerificationUnderAllocator(allocator: std.mem.Allocator, root_pem: []const u8, chain: *const fixtures.Chain) !void {
    var owner = try policy.TrustContext.init(allocator, testing.io, .{
        .source = .{ .custom_only = .{ .pem_bytes = root_pem } },
    });
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    var req = request(&.{ chain.leaf, chain.intermediate }, verifier.verifier());
    req.scratch_allocator = allocator;
    try owner.provider().verifyPeer(req);
}

test "owned PEM anchors and scratch paths survive every allocation failure" {
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    const root_pem = try fixtures.pem(testing.allocator, chain.root);
    defer testing.allocator.free(root_pem);
    try testing.checkAllAllocationFailures(testing.allocator, initializationAndVerificationUnderAllocator, .{ root_pem, &chain });
}

test "root source slices are copied and PEM framing and load bounds fail closed" {
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    var owner = blk: {
        const copy = try testing.allocator.dupe(u8, chain.root);
        defer testing.allocator.free(copy);
        const result = try context(copy);
        @memset(copy, 0);
        break :blk result;
    };
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    try owner.provider().verifyPeer(request(&.{ chain.leaf, chain.intermediate }, verifier.verifier()));

    for ([_][]const u8{
        "not a certificate",
        "-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\nAAAA",
    }) |pem| {
        try testing.expectError(error.TlsTrustStoreLoadFailed, policy.TrustContext.init(testing.allocator, testing.io, .{
            .source = .{ .custom_only = .{ .pem_bytes = pem } },
        }));
    }
    try testing.expectError(error.TlsCertificateTooLarge, policy.TrustContext.init(testing.allocator, testing.io, .{
        .source = .{ .custom_only = .{ .der_certificates = &.{chain.root} } },
        .max_certificate_der_bytes = chain.root.len - 1,
    }));
    try testing.expectError(error.TlsTrustStoreLoadFailed, policy.TrustContext.init(testing.allocator, testing.io, .{
        .source = .{ .custom_only = .{ .der_certificates = &.{ chain.root, chain.root } } },
        .max_trust_anchors = 1,
    }));
    try testing.expectError(error.TlsTrustStoreLoadFailed, policy.TrustContext.init(testing.allocator, testing.io, .{
        .source = .{ .custom_only = .{ .pem_file_path = "src/tls/fixtures/trust/not-present.pem" } },
    }));
    const root_pem = try fixtures.pem(testing.allocator, chain.root);
    defer testing.allocator.free(root_pem);
    try testing.expectError(error.TlsTrustStoreLoadFailed, policy.TrustContext.init(testing.allocator, testing.io, .{
        .source = .{ .custom_only = .{ .pem_bytes = root_pem } },
        .max_pem_bytes = root_pem.len - 1,
    }));
    var second_options = fixtures.rootOptions();
    second_options.serial = 2;
    const second = try fixtures.certificate(testing.allocator, chain.root_key, chain.root_key, second_options);
    defer testing.allocator.free(second);
    try testing.expectError(error.TlsTrustStoreLoadFailed, policy.TrustContext.init(testing.allocator, testing.io, .{
        .source = .{ .custom_only = .{ .der_certificates = &.{ chain.root, second } } },
        .max_certificate_der_bytes = chain.root.len,
        .max_trust_store_der_bytes = chain.root.len,
    }));
}

test "bounded X509 parser rejects every truncated certificate" {
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    for ([_][]const u8{ chain.root, chain.intermediate, chain.leaf }) |certificate| {
        for (0..certificate.len) |length| {
            try testing.expectError(error.TlsMalformedCertificate, x509.parse(certificate[0..length]));
        }
    }
}

test "named local PEM file and PEM bytes produce the same owned anchors" {
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    const regenerated = try fixtures.pem(testing.allocator, chain.root);
    defer testing.allocator.free(regenerated);
    try testing.expectEqualStrings(@embedFile("fixtures/trust/root_ed25519.pem"), regenerated);
    var file_owner = try policy.TrustContext.init(testing.allocator, testing.io, .{
        .source = .{ .custom_only = .{ .pem_file_path = "src/tls/fixtures/trust/root_ed25519.pem" } },
    });
    defer file_owner.deinit();
    var bytes_owner = try policy.TrustContext.init(testing.allocator, testing.io, .{
        .source = .{ .custom_only = .{ .pem_bytes = regenerated } },
    });
    defer bytes_owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    const req = request(&.{ chain.leaf, chain.intermediate }, verifier.verifier());
    try file_owner.provider().verifyPeer(req);
    try bytes_owner.provider().verifyPeer(req);
}

test "self-issued CA rollover is path-length exempt but issuer cycles cannot establish trust" {
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    var owner = try context(chain.root);
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    const rollover_key = try fixtures.Key.init(.ed25519, 4);
    var rollover_options = fixtures.intermediateOptions();
    rollover_options.issuer = rollover_options.subject;
    rollover_options.serial = 4;
    const rollover = try fixtures.certificate(testing.allocator, rollover_key, chain.intermediate_key, rollover_options);
    defer testing.allocator.free(rollover);
    const leaf = try fixtures.certificate(testing.allocator, chain.leaf_key, rollover_key, fixtures.leafOptions());
    defer testing.allocator.free(leaf);
    try owner.provider().verifyPeer(request(&.{ leaf, rollover, chain.intermediate }, verifier.verifier()));
    var limited = request(&.{ leaf, rollover, chain.intermediate }, verifier.verifier());
    limited.limits.max_path_depth = 3;
    try testing.expectError(error.TlsCertificatePathTooDeep, owner.provider().verifyPeer(limited));

    const cycle_key = try fixtures.Key.init(.ed25519, 5);
    var first_options = fixtures.intermediateOptions();
    first_options.issuer = "Cycle";
    first_options.path_length = null;
    const first = try fixtures.certificate(testing.allocator, chain.intermediate_key, cycle_key, first_options);
    defer testing.allocator.free(first);
    var second_options = fixtures.intermediateOptions();
    second_options.subject = "Cycle";
    second_options.issuer = "Fixture Intermediate";
    second_options.path_length = null;
    const second = try fixtures.certificate(testing.allocator, cycle_key, chain.intermediate_key, second_options);
    defer testing.allocator.free(second);
    try testing.expectError(error.TlsUnknownCa, owner.provider().verifyPeer(request(&.{
        chain.leaf, first, second,
    }, verifier.verifier())));
}

test "root time constraints validity boundaries and empty-subject SAN policy are explicit" {
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    var owner = try context(chain.root);
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    const leaf = try x509.parse(chain.leaf);
    var req = request(&.{ chain.leaf, chain.intermediate }, verifier.verifier());
    req.now_seconds = leaf.not_before;
    try owner.provider().verifyPeer(req);
    req.now_seconds = leaf.not_after;
    try owner.provider().verifyPeer(req);

    var expired_options = fixtures.rootOptions();
    expired_options.not_after = "260101000000Z";
    const expired_root = try fixtures.certificate(testing.allocator, chain.root_key, chain.root_key, expired_options);
    defer testing.allocator.free(expired_root);
    var expired = try context(expired_root);
    defer expired.deinit();
    try testing.expectError(error.TlsCertificateExpired, expired.provider().verifyPeer(request(&.{
        chain.leaf, chain.intermediate,
    }, verifier.verifier())));

    var options = fixtures.leafOptions();
    options.subject = "";
    const noncritical = try fixtures.certificate(testing.allocator, chain.leaf_key, chain.intermediate_key, options);
    defer testing.allocator.free(noncritical);
    try testing.expectError(error.TlsMalformedCertificate, x509.parse(noncritical));
    options.san_critical = true;
    const critical = try fixtures.certificate(testing.allocator, chain.leaf_key, chain.intermediate_key, options);
    defer testing.allocator.free(critical);
    try owner.provider().verifyPeer(request(&.{ critical, chain.intermediate }, verifier.verifier()));
}

test "one immutable trust context verifies concurrent peers without retaining request state" {
    const Worker = struct {
        provider: trust.TrustProvider,
        input: trust.VerifyPeerRequest,
        failure: ?trust.TrustError = null,
        completed: bool = false,

        fn run(self: *@This()) void {
            self.provider.verifyPeer(self.input) catch |err| {
                self.failure = err;
            };
            self.completed = true;
        }
    };
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    var owner = try context(chain.root);
    defer owner.deinit();
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    var workers: [4]Worker = undefined;
    const peer_der = [_][]const u8{ chain.leaf, chain.intermediate };
    var group: std.Io.Group = .init;
    defer group.cancel(testing.io);
    for (&workers, 0..) |*worker, i| {
        worker.* = .{
            .provider = owner.provider(),
            .input = request(&peer_der, verifier.verifier()),
        };
        if (i % 2 != 0) worker.input.expected_identity = .{ .dns_name = "wrong.example.test" };
        try group.concurrent(testing.io, Worker.run, .{worker});
    }
    try group.await(testing.io);
    for (workers, 0..) |worker, i| {
        try testing.expect(worker.completed);
        if (i % 2 != 0) {
            try testing.expectEqual(error.TlsHostnameMismatch, worker.failure.?);
        } else {
            try testing.expect(worker.failure == null);
        }
    }
    try testing.expectEqual(@as(usize, 1), owner.anchorCount());
}

test "extension and GeneralName counts have independent fixed bounds" {
    var chain = try fixtures.Chain.init(testing.allocator, .ed25519);
    defer chain.deinit();
    var options = fixtures.leafOptions();
    var oids: [x509.max_extensions - 3][3]u8 = undefined;
    var extensions: [oids.len]fixtures.Extension = undefined;
    for (&oids, &extensions, 0..) |*oid, *extension, i| {
        oid.* = .{ 0x2a, 3, @intCast(i + 1) };
        extension.* = .{ .oid = oid, .value = "\x05\x00" };
    }
    options.extra_extensions = &extensions;
    const too_many_extensions = try fixtures.certificate(testing.allocator, chain.leaf_key, chain.intermediate_key, options);
    defer testing.allocator.free(too_many_extensions);
    try testing.expectError(error.TlsCertificateConstraintViolation, x509.parse(too_many_extensions));
    var names: [x509.max_general_names + 1]fixtures.San = undefined;
    @memset(&names, .{ .dns = "api.example.test" });
    options.extra_extensions = &.{};
    options.san = &names;
    const too_many_names = try fixtures.certificate(testing.allocator, chain.leaf_key, chain.intermediate_key, options);
    defer testing.allocator.free(too_many_names);
    try testing.expectError(error.TlsCertificateConstraintViolation, x509.parse(too_many_names));
}

test "a supplied provider stays borrowed after the wrapper is deinitialized" {
    const External = struct {
        fn verify(_: *anyopaque, _: trust.VerifyPeerRequest) trust.TrustError!void {
            return error.TlsUnknownCa;
        }
    };
    var external: u8 = 0;
    const borrowed: trust.TrustProvider = .{
        .context = &external,
        .vtable = &.{ .verify_peer = External.verify },
    };
    const handle = blk: {
        var owner = try policy.TrustContext.init(testing.allocator, testing.io, .{
            .source = .{ .provider = borrowed },
        });
        defer owner.deinit();
        const provider_handle = owner.provider();
        try testing.expectEqual(@intFromPtr(&external), @intFromPtr(provider_handle.context));
        try testing.expectEqual(@as(usize, 0), owner.anchorCount());
        break :blk provider_handle;
    };
    var standard = StandardProvider.init(testing.io, testing.allocator);
    var verifier = CryptoCertificateVerifier.init(standard.provider());
    try testing.expectError(error.TlsUnknownCa, handle.verifyPeer(request(&.{"external input"}, verifier.verifier())));
}
