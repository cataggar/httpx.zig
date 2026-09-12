//! Hermetic platform-metadata integration: never accesses a system store.
const std = @import("std");
const metadata = @import("platform_trust.zig");
const policy = @import("standard_trust.zig");
const fixtures = @import("trust_fixtures.zig");
const trust = @import("trust.zig");
const StandardProvider = @import("crypto/standard.zig").StandardProvider;
const CryptoCertificateVerifier = @import("cert_crypto.zig").CryptoCertificateVerifier;

test {
    _ = @import("platform_trust_windows.zig");
    _ = @import("platform_trust_macos.zig");
    _ = @import("standard_trust_test.zig");
}

const Harness = struct {
    allocator: std.mem.Allocator,
    chain: fixtures.Chain,
    owner: policy.TrustContext,
    standard: StandardProvider,

    fn init(allocator: std.mem.Allocator) !Harness {
        var chain = try fixtures.Chain.init(allocator, .ed25519);
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
};

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
    var crypto = CryptoCertificateVerifier.init(harness.standard.provider());
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
    var spy = Spy{ .inner = crypto.verifier() };
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
