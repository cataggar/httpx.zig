//! Raw identifier hashing, separate from certificate/TLS signature policy.
//! The selected-provider adapter owns the borrowed context. No request data
//! or allocator is retained; callbacks must be safe for concurrent calls.
const std = @import("std");
const crypto = @import("crypto/provider.zig");

pub const Options = struct {
    /// Does not enable SHA-1 signatures, HMAC, HKDF, or TLS PRF operations.
    /// The selected provider must independently advertise raw SHA-1 hashing.
    allow_sha1_identifiers: bool = false,
    /// Requires independent ABI 2 provider support and deployment permission.
    allow_md5_identifiers: bool = false,
};

pub const MetadataDigest = struct {
    context: *anyopaque,
    digest_fn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        crypto.HashAlgorithm,
        []const u8,
        []u8,
    ) crypto.ProviderError!void,
    options: Options = .{},

    /// Input/output are borrowed for this synchronous call. Output has exactly
    /// the selected digest length. The adapter must release every temporary
    /// hash handle on success/failure and must not retain scratch allocations.
    /// All output bytes are cleared on every failure, including pre-dispatch.
    pub fn hash(
        self: MetadataDigest,
        scratch: std.mem.Allocator,
        algorithm: crypto.HashAlgorithm,
        input: []const u8,
        output: []u8,
    ) crypto.ProviderError!void {
        errdefer @memset(output, 0);
        if (output.len != algorithm.digestLength()) return error.InvalidDigestLength;
        if (algorithm == .sha1 and !self.options.allow_sha1_identifiers)
            return error.UnsupportedAlgorithm;
        if (algorithm == .md5 and !self.options.allow_md5_identifiers)
            return error.UnsupportedAlgorithm;
        try self.digest_fn(self.context, scratch, algorithm, input, output);
    }
};

test "metadata digest opt-in and exact output sizes precede dispatch" {
    const Fake = struct {
        calls: usize = 0,
        seen_input: usize = 0,
        fn digest(context: *anyopaque, _: std.mem.Allocator, _: crypto.HashAlgorithm, input: []const u8, output: []u8) crypto.ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            self.seen_input = @intFromPtr(input.ptr);
            @memset(output, 0x42);
        }
    };
    var fake = Fake{};
    var descriptor = MetadataDigest{ .context = &fake, .digest_fn = Fake.digest };
    var md5: [16]u8 = @splat(0xa5);
    try std.testing.expectError(error.UnsupportedAlgorithm, descriptor.hash(std.testing.allocator, .md5, "abc", &md5));
    try std.testing.expect(std.mem.allEqual(u8, &md5, 0));
    var sha1: [20]u8 = @splat(0xa5);
    const input = "owned by caller";
    try std.testing.expectError(error.UnsupportedAlgorithm, descriptor.hash(std.testing.allocator, .sha1, input, &sha1));
    try std.testing.expectEqual(@as(usize, 0), fake.calls);
    try std.testing.expect(std.mem.allEqual(u8, &sha1, 0));
    descriptor.options.allow_sha1_identifiers = true;
    try descriptor.hash(std.testing.allocator, .sha1, input, &sha1);
    try std.testing.expectEqual(@as(usize, 1), fake.calls);
    @memset(&md5, 0xa5);
    try std.testing.expectError(error.UnsupportedAlgorithm, descriptor.hash(std.testing.allocator, .md5, input, &md5));
    try std.testing.expect(std.mem.allEqual(u8, &md5, 0));
    try std.testing.expectEqual(@intFromPtr(input.ptr), fake.seen_input);
    try std.testing.expect(std.mem.allEqual(u8, &sha1, 0x42));
    var short: [31]u8 = @splat(0xa5);
    try std.testing.expectError(error.InvalidDigestLength, descriptor.hash(std.testing.allocator, .sha256, input, &short));
    try std.testing.expect(std.mem.allEqual(u8, &short, 0));
    try std.testing.expectEqual(@as(usize, 1), fake.calls);
    descriptor.options.allow_md5_identifiers = true;
    descriptor.options.allow_sha1_identifiers = false;
    try descriptor.hash(std.testing.allocator, .md5, input, &md5);
    try std.testing.expectEqual(@as(usize, 2), fake.calls);
    try std.testing.expect(std.mem.allEqual(u8, &md5, 0x42));
    try std.testing.expectError(error.UnsupportedAlgorithm, descriptor.hash(std.testing.allocator, .sha1, input, &sha1));
    try std.testing.expectEqual(@as(usize, 2), fake.calls);
}

test "metadata digest propagates provider failures without stale output or fallback" {
    const Fake = struct {
        failure: crypto.ProviderError,
        calls: usize = 0,
        fn digest(context: *anyopaque, _: std.mem.Allocator, _: crypto.HashAlgorithm, _: []const u8, output: []u8) crypto.ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            output[0] = 0xaa;
            return self.failure;
        }
    };
    for ([_]crypto.ProviderError{ error.UnsupportedAlgorithm, error.UnsupportedOperation, error.OutOfMemory, error.InternalError }) |failure| {
        var fake = Fake{ .failure = failure };
        const descriptor = MetadataDigest{
            .context = &fake,
            .digest_fn = Fake.digest,
            .options = .{ .allow_sha1_identifiers = true },
        };
        var output: [20]u8 = @splat(0xa5);
        try std.testing.expectError(failure, descriptor.hash(std.testing.allocator, .sha1, "certificate bytes", &output));
        try std.testing.expectEqual(@as(usize, 1), fake.calls);
        try std.testing.expect(std.mem.allEqual(u8, &output, 0));
    }
}
