const std = @import("std");
const testing = std.testing;
const p = @import("crypto/provider.zig");
const Standard = @import("crypto/standard.zig").StandardProvider;
const Adapter = @import("cert_crypto.zig").CryptoCertificateVerifier;
const metadata = @import("metadata_digest.zig");
const Binding = @import("policy_binding.zig").PolicyBinding;
const trust = @import("trust.zig");

const profiles = [_]metadata.Options{
    .{},
    .{ .allow_sha1_identifiers = true },
    .{ .allow_md5_identifiers = true },
    .{ .allow_sha1_identifiers = true, .allow_md5_identifiers = true },
};
const algorithms = [_]p.HashAlgorithm{ .sha1, .md5, .sha256 };

fn permitted(options: metadata.Options, owner_md5: bool, algorithm: p.HashAlgorithm) bool {
    return switch (algorithm) {
        .sha1 => options.allow_sha1_identifiers,
        .md5 => owner_md5 and options.allow_md5_identifiers,
        else => true,
    };
}

fn check(result: p.ProviderError!void, allowed: bool, algorithm: p.HashAlgorithm, output: []const u8) !void {
    if (!allowed) {
        try testing.expectError(error.UnsupportedAlgorithm, result);
        try testing.expect(std.mem.allEqual(u8, output, 0));
        return;
    }
    try result;
    const expected: []const u8 = switch (algorithm) {
        .sha1 => "\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d",
        .md5 => "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72",
        .sha256 => "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad",
        else => return error.UnexpectedAlgorithm,
    };
    try testing.expectEqualSlices(u8, expected, output);
}

test "metadata ABI2 owner and independent SHA1 MD5 gates cover all captured callbacks" {
    for ([_]bool{ false, true }) |owner_md5| {
        var standard = Standard.initWithOptions(testing.io, testing.allocator, .{ .allow_md5_identifier_hash = owner_md5 });
        const provider = standard.provider();
        const before = try provider.capabilities();
        var adapter = Adapter.init(provider);
        for (profiles, 0..) |options, index| {
            const hasher = adapter.metadataHasher(options);
            try testing.expectEqual(adapter.verifier().context, hasher.context);
            for (profiles[0..index]) |other| try testing.expect(hasher.digest_fn != adapter.metadataHasher(other).digest_fn);
            var relaxed = hasher;
            relaxed.options = profiles[3];
            var reduced = hasher;
            reduced.options = .{};
            for (algorithms) |algorithm| {
                var bytes: [32]u8 = undefined;
                const output = bytes[0..algorithm.digestLength()];
                const allowed = permitted(options, owner_md5, algorithm);
                @memset(output, 0xa5);
                try check(adapter.digestMetadata(testing.allocator, algorithm, "abc", output, .{
                    .allow_sha1_identifiers = options.allow_sha1_identifiers,
                    .allow_md5_identifiers = options.allow_md5_identifiers,
                }), allowed, algorithm, output);
                @memset(output, 0xa5);
                try check(hasher.hash(testing.allocator, algorithm, "abc", output), allowed, algorithm, output);
                @memset(output, 0xa5);
                try check(hasher.digest_fn(hasher.context, testing.allocator, algorithm, "abc", output), allowed, algorithm, output);
                @memset(output, 0xa5);
                try check(relaxed.hash(testing.allocator, algorithm, "abc", output), allowed, algorithm, output);
                @memset(output, 0xa5);
                try check(relaxed.digest_fn(relaxed.context, testing.allocator, algorithm, "abc", output), allowed, algorithm, output);
                @memset(output, 0xa5);
                try check(reduced.hash(testing.allocator, algorithm, "abc", output), algorithm == .sha256, algorithm, output);
            }
            try testing.expectError(error.UnsupportedAlgorithm, adapter.verifier().verify(.{
                .algorithm = .{ .oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04", .parameters_der = "\x05\x00" },
                .issuer_spki_der = "",
                .tbs_certificate_der = "",
                .signature = "",
            }));
        }
        try testing.expect(std.meta.eql(before, try provider.capabilities()));
        for (std.enums.values(p.SignatureScheme)) |scheme| try testing.expect(scheme.hashAlgorithm() != .md5);
    }
}

test "metadata ABI2 exact MD5 lengths and OOM clear every invocation surface" {
    var standard = Standard.initWithOptions(testing.io, testing.allocator, .{ .allow_md5_identifier_hash = true });
    var adapter = Adapter.init(standard.provider());
    for (profiles) |options| {
        const hasher = adapter.metadataHasher(options);
        for ([_]bool{ false, true }) |direct| {
            var bytes: [17]u8 = undefined;
            for ([_]usize{ 0, 1, 15, 17 }) |length| {
                @memset(&bytes, 0xa5);
                const output = bytes[0..length];
                const result = if (direct)
                    hasher.digest_fn(hasher.context, testing.allocator, .md5, "abc", output)
                else
                    hasher.hash(testing.allocator, .md5, "abc", output);
                try testing.expectError(error.InvalidDigestLength, result);
                try testing.expect(std.mem.allEqual(u8, output, 0));
                try testing.expect(std.mem.allEqual(u8, bytes[length..], 0xa5));
            }
            @memset(&bytes, 0xa5);
            const result = if (direct)
                hasher.digest_fn(hasher.context, testing.failing_allocator, .md5, "abc", bytes[0..16])
            else
                hasher.hash(testing.failing_allocator, .md5, "abc", bytes[0..16]);
            try testing.expectError(if (options.allow_md5_identifiers) error.OutOfMemory else error.UnsupportedAlgorithm, result);
            try testing.expect(std.mem.allEqual(u8, bytes[0..16], 0));
            try testing.expectEqual(@as(u8, 0xa5), bytes[16]);
        }
    }
    const AllocationCase = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var owner = Standard.initWithOptions(testing.io, allocator, .{ .allow_md5_identifier_hash = true });
            var selected = Adapter.init(owner.provider());
            var output: [16]u8 = undefined;
            try selected.digestMetadata(allocator, .md5, "abc", &output, .{ .allow_md5_identifiers = true });
            const hasher = selected.metadataHasher(.{ .allow_md5_identifiers = true });
            try hasher.hash(allocator, .md5, "abc", &output);
            try hasher.digest_fn(hasher.context, allocator, .md5, "abc", &output);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, AllocationCase.run, .{});
}

test "metadata ABI2 concurrent bindings retain four independent captured permissions" {
    const Fixture = struct {
        options: metadata.Options,

        fn verify(context: *const anyopaque, request: trust.VerifyPeerRequest, hasher: metadata.MetadataDigest) trust.TrustError!void {
            const self: *const @This() = @ptrCast(@alignCast(context));
            for (algorithms) |algorithm| {
                var bytes: [32]u8 = @splat(0xa5);
                const output = bytes[0..algorithm.digestLength()];
                check(hasher.hash(request.scratch_allocator, algorithm, "abc", output), permitted(self.options, true, algorithm), algorithm, output) catch
                    return error.TlsCertificateConstraintViolation;
            }
        }
    };
    const Worker = struct {
        binding: *Binding,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            for (0..32) |_| {
                self.binding.provider().verifyPeer(.{
                    .role = .server,
                    .chain_der = &.{"fixture DER"},
                    .expected_identity = .{ .dns_name = "localhost" },
                    .now_seconds = 1_800_000_000,
                    .signature_verifier = self.binding.signatureVerifier(),
                    .scratch_allocator = testing.allocator,
                }) catch |err| {
                    self.failure = err;
                    return;
                };
            }
        }
    };
    var standard = Standard.initWithOptions(testing.io, testing.allocator, .{ .allow_md5_identifier_hash = true });
    var adapter = Adapter.init(standard.provider());
    var fixtures: [4]Fixture = undefined;
    var bindings: [4]Binding = undefined;
    var workers: [4]Worker = undefined;
    for (profiles, 0..) |options, index| {
        fixtures[index] = .{ .options = options };
        bindings[index] = try Binding.init(&fixtures[index], Fixture.verify, adapter.verifier(), adapter.metadataHasher(options));
        workers[index] = .{ .binding = &bindings[index] };
    }
    var threads: [4]std.Thread = undefined;
    var started: usize = 0;
    errdefer for (threads[0..started]) |thread| thread.join();
    for (&workers, &threads) |*worker, *thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{worker});
        started += 1;
    }
    for (threads) |thread| thread.join();
    started = 0;
    for (workers) |worker| if (worker.failure) |err| return err;
}

test "metadata ABI2 admission never equates ABI1 or A B provider identity" {
    var first = Standard.initWithOptions(testing.io, testing.allocator, .{ .allow_md5_identifier_hash = true });
    var second = Standard.initWithOptions(testing.io, testing.allocator, .{ .allow_md5_identifier_hash = true });
    for ([_]u32{ 1, 2 }) |version| {
        var selected = first.provider();
        selected.abi_version = version;
        var adapter = Adapter.init(selected);
        try selected.validate();
        try testing.expect(adapter.matchesProvider(selected));
        var other_version = selected;
        other_version.abi_version = if (version == 1) 2 else 1;
        try other_version.validate();
        try testing.expect(!adapter.matchesProvider(other_version));
        var other_context = selected;
        other_context.context = second.provider().context;
        try testing.expect(!adapter.matchesProvider(other_context));
        var copy = selected.vtable.*;
        var other_vtable = selected;
        other_vtable.vtable = &copy;
        try testing.expect(!adapter.matchesProvider(other_vtable));
        var output: [16]u8 = @splat(0xa5);
        try check(adapter.metadataHasher(profiles[3]).hash(testing.allocator, .md5, "abc", &output), version == 2, .md5, &output);
    }
}
