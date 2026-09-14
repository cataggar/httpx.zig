//! Hermetic platform-metadata integration: never accesses a system store.
const std = @import("std");
const metadata = @import("platform_trust.zig");
const policy = @import("standard_trust.zig");
const fixtures = @import("trust_fixtures.zig");
const trust = @import("trust.zig");
const StandardProvider = @import("crypto/standard.zig").StandardProvider;
const CryptoCertificateVerifier = @import("cert_crypto.zig").CryptoCertificateVerifier;
const crypto = @import("crypto/provider.zig");
const digest = @import("metadata_digest.zig");

test {
    _ = @import("platform_trust_windows.zig");
    _ = @import("platform_trust_macos.zig");
    _ = @import("standard_trust_test.zig");
    _ = @import("policy_binding.zig");
    _ = @import("windows_ctl_test.zig");
}

/// Conformance adapter for the agreed two-method contract. Shared production
/// adapter/runtime implementation belongs to cert_crypto's owner.
const PairedAdapter = struct {
    selected: crypto.CryptoProvider,
    hashes: std.atomic.Value(usize) = .init(0),
    signatures: std.atomic.Value(usize) = .init(0),
    hash_failure: ?crypto.ProviderError = null,

    pub fn verifier(self: *PairedAdapter) trust.CertificateSignatureVerifier {
        return .{ .context = self, .vtable = &.{ .verify = verify } };
    }

    pub fn metadataHasher(self: *PairedAdapter, options: digest.Options) digest.MetadataDigest {
        return .{ .context = self, .digest_fn = hash, .options = options };
    }

    fn verify(context: *anyopaque, input: @import("cert_signature.zig").VerifyCertificateSignatureRequest) @import("cert_signature.zig").CertificateSignatureError!void {
        const self: *PairedAdapter = @ptrCast(@alignCast(context));
        _ = self.signatures.fetchAdd(1, .monotonic);
        var bridge = CryptoCertificateVerifier.init(self.selected);
        try bridge.verifier().verify(input);
    }

    fn hash(context: *anyopaque, allocator: std.mem.Allocator, algorithm: crypto.HashAlgorithm, input: []const u8, output: []u8) crypto.ProviderError!void {
        const self: *PairedAdapter = @ptrCast(@alignCast(context));
        _ = self.hashes.fetchAdd(1, .monotonic);
        errdefer @memset(output, 0);
        if (self.hash_failure) |err| {
            output[0] = 0xa5;
            return err;
        }
        var handle = try self.selected.hashCreate(allocator, algorithm);
        defer handle.deinit();
        try handle.update(input);
        try handle.snapshot(output);
    }
};

const Harness = struct {
    allocator: std.mem.Allocator,
    chain: fixtures.Chain,
    owner: policy.TrustContext,
    standard: StandardProvider,

    fn init(allocator: std.mem.Allocator) !Harness {
        return initScheme(allocator, .ed25519);
    }

    fn initScheme(allocator: std.mem.Allocator, scheme: fixtures.Scheme) !Harness {
        var chain = try fixtures.Chain.init(allocator, scheme);
        errdefer chain.deinit();
        var owner = try policy.TrustContext.init(allocator, std.testing.io, .{
            .source = .{ .custom_only = .{ .der_certificates = &.{chain.root} } },
        });
        owner.platform_snapshot = metadata.Snapshot.init(allocator, .{});
        return .{
            .allocator = allocator,
            .chain = chain,
            .owner = owner,
            .standard = StandardProvider.init(std.testing.io, allocator),
        };
    }

    fn deinit(self: *Harness) void {
        self.owner.deinit();
        self.chain.deinit();
    }

    fn request(self: *Harness, verifier: trust.CertificateSignatureVerifier, chain: []const []const u8) trust.VerifyPeerRequest {
        return .{
            .role = .server,
            .chain_der = chain,
            .expected_identity = .{ .dns_name = "api.example.test" },
            .now_seconds = 1_800_000_000,
            .signature_verifier = verifier,
            .scratch_allocator = self.allocator,
        };
    }

    fn verify(self: *Harness) !void {
        var verifier = CryptoCertificateVerifier.init(self.standard.provider());
        try self.owner.provider().verifyPeer(self.request(verifier.verifier(), &.{ self.chain.leaf, self.chain.intermediate }));
    }

    fn fingerprint(self: *Harness, adapter: *PairedAdapter, bytes: []const u8, algorithm: crypto.HashAlgorithm, windows: metadata.Windows) !void {
        var output: [64]u8 = undefined;
        try adapter.metadataHasher(.{ .allow_sha1_identifiers = true }).hash(self.allocator, algorithm, bytes, output[0..algorithm.digestLength()]);
        const entry = try metadata.FingerprintEntry.init(algorithm, output[0..algorithm.digestLength()], windows);
        try self.owner.platform_snapshot.?.addFingerprintList(.{
            .algorithm = algorithm,
            .this_update = 1_700_000_000,
            .next_update = 1_900_000_000,
            .entries = &.{entry},
        });
    }
};

test "canonical Disallowed P15 and P25 deny every path position including custom duplicates" {
    const disallowed = @import("windows_disallowed.zig");
    const ctl = @import("windows_ctl.zig");
    const ctlf = @import("ctl_fixtures.zig");
    for ([_]bool{ false, true }) |key_identity| {
        for ([_]bool{ false, true }) |matches| {
            for (0..3) |position| {
                var harness = try Harness.initScheme(std.testing.allocator, .ecdsa_p256);
                defer harness.deinit();
                harness.standard.options.allow_md5_identifier_hash = true;
                var adapter = CryptoCertificateVerifier.init(harness.standard.provider());
                const certificates = [_][]const u8{ harness.chain.leaf, harness.chain.intermediate, harness.chain.root };
                const inputs = try disallowed.parse(certificates[position]);
                const hash: crypto.HashAlgorithm = if (key_identity) .md5 else inputs.signature_hash;
                var identifier: [64]u8 = undefined;
                const options: digest.Options = .{ .allow_md5_identifiers = true };
                try adapter.metadataHasher(options).hash(harness.allocator, hash, if (key_identity) inputs.public_key_bits else inputs.tbs_der, identifier[0..hash.digestLength()]);
                if (!matches) identifier[0] ^= 1;
                const encoded = try ctlf.content(harness.allocator, .{
                    .usage_oid = ctl.disallowed_usage,
                    .algorithm_oid = ctl.disallowed_hash,
                    .algorithm_parameters = "\x05\x00",
                    .entries = &.{.{
                        .identifier = identifier[0..hash.digestLength()],
                        .attributes = &.{.{ .id = 9, .value = "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01" }},
                    }},
                });
                defer harness.allocator.free(encoded);
                try ctl.append(&harness.owner.platform_snapshot.?, .disallowed, encoded);
                var binding = try harness.owner.bind(&adapter, options);
                const result = binding.provider().verifyPeer(harness.request(binding.signatureVerifier(), &.{ harness.chain.leaf, harness.chain.intermediate }));
                if (matches)
                    try std.testing.expectError(error.TlsCertificateConstraintViolation, result)
                else
                    try result;
            }
        }
    }
}

test "canonical Disallowed rejects unavailable Ed25519 P15 without changing custom-only trust" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    // Real custom-only construction has no platform snapshot; the harness adds
    // one explicitly to exercise Windows restrictions without reading the OS.
    harness.owner.platform_snapshot.?.deinit();
    harness.owner.platform_snapshot = null;
    try harness.verify();
    harness.owner.platform_snapshot = metadata.Snapshot.init(harness.allocator, .{});
    try harness.owner.platform_snapshot.?.addFingerprintList(.{
        .kind = .disallowed,
        .identity = .windows_disallowed,
        .this_update = 1_700_000_000,
        .entries = &.{},
    });
    harness.standard.options.allow_md5_identifier_hash = true;
    var adapter = CryptoCertificateVerifier.init(harness.standard.provider());
    var binding = try harness.owner.bind(&adapter, .{ .allow_md5_identifiers = true });
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, binding.provider().verifyPeer(
        harness.request(binding.signatureVerifier(), &.{ harness.chain.leaf, harness.chain.intermediate }),
    ));
}

test "canonical binding enforces fingerprint restrictions at every selected path position" {
    for ([_]crypto.HashAlgorithm{ .sha1, .sha256 }) |algorithm| {
        for (0..3) |position| {
            var harness = try Harness.init(std.testing.allocator);
            defer harness.deinit();
            var adapter = PairedAdapter{ .selected = harness.standard.provider() };
            const certificates = [_][]const u8{ harness.chain.leaf, harness.chain.intermediate, harness.chain.root };
            try harness.fingerprint(&adapter, certificates[position], algorithm, .{ .roles = 0 });
            var binding = try harness.owner.bind(&adapter, .{ .allow_sha1_identifiers = true });
            const request = harness.request(binding.signatureVerifier(), &.{ harness.chain.leaf, harness.chain.intermediate });
            try std.testing.expectError(error.TlsCertificateConstraintViolation, binding.provider().verifyPeer(request));
        }
    }
}

test "canonical empty104 excludes only matched subjects without approving affected custom anchors" {
    const ctl = @import("windows_ctl.zig");
    const ctl_fixtures = @import("ctl_fixtures.zig");
    for ([_]bool{ false, true }) |matches| {
        for (0..3) |position| {
            var harness = try Harness.init(std.testing.allocator);
            defer harness.deinit();
            var adapter = PairedAdapter{ .selected = harness.standard.provider() };
            const certificates = [_][]const u8{ harness.chain.leaf, harness.chain.intermediate, harness.chain.root };
            var identifier: [20]u8 = undefined;
            try adapter.metadataHasher(.{ .allow_sha1_identifiers = true }).hash(harness.allocator, .sha1, certificates[position], &identifier);
            if (!matches) identifier[0] ^= 1;
            const encoded = try ctl_fixtures.content(harness.allocator, .{
                .entries = &.{.{ .identifier = &identifier, .attributes = &.{.{ .id = 104, .value = "" }} }},
            });
            defer harness.allocator.free(encoded);
            try ctl.append(&harness.owner.platform_snapshot.?, .authroot, encoded);
            var binding = try harness.owner.bind(&adapter, .{ .allow_sha1_identifiers = true });
            const request = harness.request(binding.signatureVerifier(), &.{ harness.chain.leaf, harness.chain.intermediate });
            if (matches) {
                try std.testing.expectError(error.TlsCertificateConstraintViolation, binding.provider().verifyPeer(request));
            } else {
                try binding.provider().verifyPeer(request);
            }
        }
    }
}

test "canonical binding requires metadata opt-in and the original adapter handle" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var adapter = PairedAdapter{ .selected = harness.standard.provider() };
    try harness.fingerprint(&adapter, harness.chain.root, .sha1, .{});
    adapter.hashes.store(0, .monotonic);
    var binding = try harness.owner.bind(&adapter, .{ .allow_sha1_identifiers = true });
    var request = harness.request(binding.signatureVerifier(), &.{ harness.chain.leaf, harness.chain.intermediate });
    try std.testing.expectError(error.TlsInvalidTrustConfiguration, harness.owner.provider().verifyPeer(request));
    var disabled = try harness.owner.bind(&adapter, .{});
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, disabled.provider().verifyPeer(request));
    try std.testing.expectEqual(@as(usize, 0), adapter.hashes.load(.monotonic));
    try binding.provider().verifyPeer(request);
    const hashes = adapter.hashes.load(.monotonic);
    const signatures = adapter.signatures.load(.monotonic);
    var same_backend_new_adapter = PairedAdapter{ .selected = harness.standard.provider() };
    request.signature_verifier = same_backend_new_adapter.verifier();
    try std.testing.expectError(error.TlsInvalidTrustConfiguration, binding.provider().verifyPeer(request));
    try std.testing.expectEqual(hashes, adapter.hashes.load(.monotonic));
    try std.testing.expectEqual(signatures, adapter.signatures.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), same_backend_new_adapter.hashes.load(.monotonic));
}

test "a fingerprint match never adds an anchor for an otherwise untrusted chain" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    const other_key = try fixtures.Key.init(.ed25519, 7);
    var options = fixtures.rootOptions();
    options.subject = "Unrelated Root";
    options.issuer = options.subject;
    const other_root = try fixtures.certificate(std.testing.allocator, other_key, other_key, options);
    defer std.testing.allocator.free(other_root);
    var owner = try policy.TrustContext.init(std.testing.allocator, std.testing.io, .{
        .source = .{ .custom_only = .{ .der_certificates = &.{other_root} } },
    });
    owner.platform_snapshot = metadata.Snapshot.init(std.testing.allocator, .{});
    harness.owner.deinit();
    harness.owner = owner;
    var adapter = PairedAdapter{ .selected = harness.standard.provider() };
    try harness.fingerprint(&adapter, harness.chain.root, .sha256, .{});
    try std.testing.expectEqual(@as(usize, 1), harness.owner.anchorCount());
    try std.testing.expectEqual(@as(usize, 0), harness.owner.platform_snapshot.?.entries.items.len);
    var binding = try harness.owner.bind(&adapter, .{});
    const request = harness.request(binding.signatureVerifier(), &.{ harness.chain.leaf, harness.chain.intermediate, harness.chain.root });
    try std.testing.expectError(error.TlsUnknownCa, binding.provider().verifyPeer(request));
}

test "paired fingerprint verification propagates hash allocation failure without fallback" {
    const Test = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var harness = try Harness.init(allocator);
            defer harness.deinit();
            var adapter = PairedAdapter{ .selected = harness.standard.provider() };
            try harness.fingerprint(&adapter, harness.chain.root, .sha1, .{});
            var binding = try harness.owner.bind(&adapter, .{ .allow_sha1_identifiers = true });
            try binding.provider().verifyPeer(harness.request(binding.signatureVerifier(), &.{ harness.chain.leaf, harness.chain.intermediate }));
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var producer = PairedAdapter{ .selected = harness.standard.provider() };
    try harness.fingerprint(&producer, harness.chain.root, .sha256, .{});
    var refusing = PairedAdapter{ .selected = harness.standard.provider(), .hash_failure = error.UnsupportedAlgorithm };
    var binding = try harness.owner.bind(&refusing, .{});
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, binding.provider().verifyPeer(
        harness.request(binding.signatureVerifier(), &.{ harness.chain.leaf, harness.chain.intermediate }),
    ));
    try std.testing.expectEqual(@as(usize, 1), refusing.hashes.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), refusing.signatures.load(.monotonic));
}

test "paired view preserves caller-supplied ABI-v1 trust callbacks" {
    const External = struct {
        calls: usize = 0,
        fn verify(context: *anyopaque, _: trust.VerifyPeerRequest) trust.TrustError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            return error.TlsHostnameMismatch;
        }
    };
    var external = External{};
    var owner = try policy.TrustContext.init(std.testing.allocator, std.testing.io, .{
        .source = .{ .provider = .{ .context = &external, .vtable = &.{ .verify_peer = External.verify } } },
    });
    defer owner.deinit();
    var standard = StandardProvider.init(std.testing.io, std.testing.allocator);
    var adapter = PairedAdapter{ .selected = standard.provider() };
    var binding = try owner.bind(&adapter, .{});
    try std.testing.expectError(error.TlsHostnameMismatch, binding.provider().verifyPeer(.{
        .role = .server,
        .chain_der = &.{"owned by external provider"},
        .expected_identity = .{ .dns_name = "api.example.test" },
        .now_seconds = 1_800_000_000,
        .signature_verifier = binding.signatureVerifier(),
        .scratch_allocator = std.testing.allocator,
    }));
    try std.testing.expectEqual(@as(usize, 1), external.calls);
    try std.testing.expectEqual(@as(usize, 0), adapter.hashes.load(.monotonic));
}

test "paired fingerprint state and current time remain isolated across concurrent requests" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var adapter = PairedAdapter{ .selected = harness.standard.provider() };
    try harness.fingerprint(&adapter, harness.chain.root, .sha256, .{ .disallow_at = 1_800_000_001 });
    var binding = try harness.owner.bind(&adapter, .{});
    const Worker = struct {
        provider: trust.TrustProvider,
        request: trust.VerifyPeerRequest,
        failure: ?trust.TrustError = null,
        fn run(self: *@This()) void {
            self.provider.verifyPeer(self.request) catch |err| {
                self.failure = err;
            };
        }
    };
    var workers: [4]Worker = undefined;
    const chain = [_][]const u8{ harness.chain.leaf, harness.chain.intermediate };
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    for (&workers, 0..) |*worker, i| {
        worker.* = .{ .provider = binding.provider(), .request = harness.request(binding.signatureVerifier(), &chain) };
        worker.request.now_seconds += @intCast(i % 2);
        try group.concurrent(std.testing.io, Worker.run, .{worker});
    }
    try group.await(std.testing.io);
    for (workers, 0..) |worker, i| {
        if (i % 2 == 0) {
            try std.testing.expect(worker.failure == null);
        } else {
            try std.testing.expectEqual(error.TlsCertificateConstraintViolation, worker.failure.?);
        }
    }
    try binding.provider().verifyPeer(harness.request(binding.signatureVerifier(), &chain));
}

test "program-root membership cannot be replaced by an unrelated AuthRoot list" {
    for ([_]bool{ false, true }) |explicit_custom| {
        var harness = try Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.owner.anchors[0].custom = explicit_custom;
        const snapshot = &harness.owner.platform_snapshot.?;
        const index = try snapshot.add(harness.chain.root, true);
        snapshot.entries.items[index].authroot_program = true;
        try snapshot.addFingerprintList(.{
            .kind = .authroot,
            .algorithm = .sha256,
            .this_update = 1_700_000_000,
            .entries = &.{},
        });
        var adapter = PairedAdapter{ .selected = harness.standard.provider() };
        var binding = try harness.owner.bind(&adapter, .{});
        const request = harness.request(binding.signatureVerifier(), &.{ harness.chain.leaf, harness.chain.intermediate });
        if (explicit_custom) {
            try binding.provider().verifyPeer(request);
        } else {
            try std.testing.expectError(error.TlsCertificateConstraintViolation, binding.provider().verifyPeer(request));
        }
    }
}

test "platform distrust checks leaf intermediate and custom duplicate root" {
    for (0..3) |position| {
        var harness = try Harness.init(std.testing.allocator);
        defer harness.deinit();
        try harness.verify();
        const certificates = [_][]const u8{ harness.chain.leaf, harness.chain.intermediate, harness.chain.root };
        const snapshot = &harness.owner.platform_snapshot.?;
        const index = try snapshot.add(certificates[position], false);
        snapshot.entries.items[index].windows = .{ .roles = 0 };
        try std.testing.expectError(error.TlsCertificateConstraintViolation, harness.verify());
    }
}

test "Windows root purpose and cutoff restrictions survive custom-root merging" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    const snapshot = &harness.owner.platform_snapshot.?;
    const index = try snapshot.add(harness.chain.root, true);
    const entry = &snapshot.entries.items[index];
    entry.windows = .{ .roles = 1, .disallow_at = 1_800_000_001 };
    try harness.verify();
    entry.windows.?.disallow_at = 1_800_000_000;
    try std.testing.expectError(error.TlsCertificateConstraintViolation, harness.verify());
    entry.windows = .{ .roles = 2 };
    try std.testing.expectError(error.TlsCertificateConstraintViolation, harness.verify());
    entry.windows = .{ .unsupported = true };
    try std.testing.expectError(error.TlsCertificateConstraintViolation, harness.verify());
}

test "macOS conditional root grant uses selected verifier including self signature" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    const snapshot = &harness.owner.platform_snapshot.?;
    const index = try snapshot.add(harness.chain.root, true);
    var rule = metadata.Rule{ .roles = 1, .key_usage = 8 };
    try rule.setHostname("api.example.test");
    try snapshot.setDomain(index, 0, &.{rule});
    var crypto_bridge = CryptoCertificateVerifier.init(harness.standard.provider());
    const SignatureError = @import("cert_signature.zig").CertificateSignatureError;
    const Spy = struct {
        inner: trust.CertificateSignatureVerifier,
        calls: usize = 0,
        reject: bool = false,
        fn verify(context: *anyopaque, request: @import("cert_signature.zig").VerifyCertificateSignatureRequest) SignatureError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            if (self.reject) return error.InvalidSignature;
            try self.inner.verify(request);
        }
    };
    var spy = Spy{ .inner = crypto_bridge.verifier() };
    const verifier: trust.CertificateSignatureVerifier = .{ .context = &spy, .vtable = &.{ .verify = Spy.verify } };
    var request = harness.request(verifier, &.{ harness.chain.leaf, harness.chain.intermediate });
    try harness.owner.provider().verifyPeer(request);
    try std.testing.expectEqual(@as(usize, 3), spy.calls);
    spy.reject = true;
    try std.testing.expectError(error.TlsCertificateSignatureInvalid, harness.owner.provider().verifyPeer(request));
    request.expected_identity = .{ .dns_name = "other.example.test" };
    try std.testing.expectError(error.TlsHostnameMismatch, harness.owner.provider().verifyPeer(request));
}

test "macOS metadata allocation and path scratch failures preserve ownership" {
    const Test = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var harness = try Harness.init(allocator);
            defer harness.deinit();
            const snapshot = &harness.owner.platform_snapshot.?;
            const index = try snapshot.add(harness.chain.root, true);
            var rule = metadata.Rule{};
            try rule.setHostname("api.example.test");
            try snapshot.setDomain(index, 0, &.{rule});
            try harness.verify();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
}

test "immutable platform cutoff metadata isolates concurrent request times" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    const snapshot = &harness.owner.platform_snapshot.?;
    const index = try snapshot.add(harness.chain.root, true);
    snapshot.entries.items[index].windows = .{ .disallow_at = 1_800_000_001 };
    var verifier = CryptoCertificateVerifier.init(harness.standard.provider());
    const Worker = struct {
        provider: trust.TrustProvider,
        input: trust.VerifyPeerRequest,
        failure: ?trust.TrustError = null,
        fn run(self: *@This()) void {
            self.provider.verifyPeer(self.input) catch |err| {
                self.failure = err;
            };
        }
    };
    var workers: [4]Worker = undefined;
    const chain = [_][]const u8{ harness.chain.leaf, harness.chain.intermediate };
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    for (&workers, 0..) |*worker, i| {
        worker.* = .{
            .provider = harness.owner.provider(),
            .input = harness.request(verifier.verifier(), &chain),
        };
        worker.input.now_seconds += @intCast(i % 2);
        try group.concurrent(std.testing.io, Worker.run, .{worker});
    }
    try group.await(std.testing.io);
    for (workers, 0..) |worker, i| {
        if (i % 2 == 0) {
            try std.testing.expect(worker.failure == null);
        } else {
            try std.testing.expectEqual(error.TlsCertificateConstraintViolation, worker.failure.?);
        }
    }
    try harness.verify();
}
