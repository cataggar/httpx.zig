const std = @import("std");
const ctl = @import("windows_ctl.zig");
const fixtures = @import("ctl_fixtures.zig");
const platform = @import("platform_trust.zig");
const digest = @import("metadata_digest.zig");
const crypto = @import("crypto/provider.zig");
const allocator = std.testing.allocator;

test {
    _ = @import("ctl_tail_diagnostic.zig");
}

const identifier: [20]u8 = @splat(1);
const server_eku = "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01";
const client_eku = "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02";
const use: platform.Use = .{ .role = .server, .identity = null, .now_seconds = 1_800_000_000, .issuer = true, .self_issued = true };

fn hash(_: *anyopaque, _: std.mem.Allocator, _: crypto.HashAlgorithm, _: []const u8, output: []u8) crypto.ProviderError!void {
    @memset(output, 1);
}

test "AuthRoot CTL decoding retains restrictions rather than installing anchors" {
    const encoded = try fixtures.content(allocator, .{ .entries = &.{.{
        .identifier = &identifier,
        .attributes = &.{
            .{ .id = 9, .value = server_eku },
            .{ .id = 98, .value = &@as([32]u8, @splat(1)) },
            .{ .id = 20, .value = "locator" },
            .{ .id = 29, .value = &@as([16]u8, @splat(2)) },
        },
    }} });
    defer allocator.free(encoded);
    var snapshot = platform.Snapshot.init(allocator, .{});
    defer snapshot.deinit();
    try ctl.append(&snapshot, .authroot, encoded);
    try std.testing.expectEqual(@as(usize, 0), snapshot.entries.items.len);
    try std.testing.expectEqual(@as(usize, 1), snapshot.fingerprint_entries);
    var context: u8 = 0;
    const hasher = digest.MetadataDigest{ .context = &context, .digest_fn = hash, .options = .{ .allow_sha1_identifiers = true } };
    try std.testing.expectEqual(platform.Decision.anchor, try snapshot.check("certificate", use, hasher, allocator));
    var client = use;
    client.role = .client;
    try std.testing.expectEqual(platform.Decision.deny, try snapshot.check("certificate", client, hasher, allocator));
}

test "Disallowed CTL entries remain denied regardless of permission-like attributes" {
    const encoded = try fixtures.content(allocator, .{
        .usage_oid = ctl.disallowed_usage,
        .entries = &.{.{ .identifier = &identifier, .attributes = &.{.{ .id = 9, .value = server_eku }} }},
    });
    defer allocator.free(encoded);
    var snapshot = platform.Snapshot.init(allocator, .{});
    defer snapshot.deinit();
    try ctl.append(&snapshot, .disallowed, encoded);
    try std.testing.expectEqual(@as(u2, 0), snapshot.fingerprint_lists.items[0].entries[0].policy.roles);
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, .authroot, encoded));
}

test "CTL purpose cutoff and unsupported issuance policies are not erased" {
    var time: [8]u8 = undefined;
    std.mem.writeInt(u64, &time, @as(u64, 1_800_000_000 + 11_644_473_600) * 10_000_000, .little);
    inline for (.{ @as(u32, 104), 128, 126, 127, 83, 84, 105, 122 }) |id| {
        const encoded = try fixtures.content(allocator, .{ .entries = &.{.{
            .identifier = &identifier,
            .attributes = &.{.{ .id = id, .value = if (id == 122) server_eku else &time }},
        }} });
        defer allocator.free(encoded);
        var snapshot = platform.Snapshot.init(allocator, .{});
        defer snapshot.deinit();
        try ctl.append(&snapshot, .authroot, encoded);
        try std.testing.expect(!snapshot.fingerprint_lists.items[0].entries[0].policy.permits(use));
    }
}

test "CTL absent empty104 and zero FILETIME remain distinct" {
    const cases = [_]struct {
        attributes: []const fixtures.Attribute,
        unsupported: bool,
        cutoff: ?i64,
    }{
        .{ .attributes = &.{}, .unsupported = false, .cutoff = null },
        .{ .attributes = &.{.{ .id = 104, .value = "" }}, .unsupported = true, .cutoff = null },
        .{ .attributes = &.{.{ .id = 104, .value = "\x00" ** 8 }}, .unsupported = false, .cutoff = -11_644_473_600 },
    };
    for (cases) |case| {
        const encoded = try fixtures.content(allocator, .{ .entries = &.{.{ .identifier = &identifier, .attributes = case.attributes }} });
        defer allocator.free(encoded);
        var snapshot = platform.Snapshot.init(allocator, .{});
        defer snapshot.deinit();
        try ctl.append(&snapshot, .authroot, encoded);
        const actual = snapshot.fingerprint_lists.items[0].entries[0].policy;
        try std.testing.expectEqual(case.unsupported, actual.unsupported);
        try std.testing.expectEqual(case.cutoff, actual.disallow_at);
        try std.testing.expectEqual(@as(usize, 0), snapshot.entries.items.len);
    }
}

test "CTL empty104 preserves purpose cutoff native policy and Disallowed denial" {
    var time: [8]u8 = undefined;
    std.mem.writeInt(u64, &time, @as(u64, 1_800_000_000 + 11_644_473_600) * 10_000_000, .little);
    const attributes = [_]fixtures.Attribute{
        .{ .id = 9, .value = server_eku },
        .{ .id = 122, .value = client_eku },
        .{ .id = 128, .value = &time },
        .{ .id = 104, .value = "" },
    };
    for ([_]platform.FingerprintList.Kind{ .authroot, .disallowed }) |kind| {
        const encoded = try fixtures.content(allocator, .{
            .usage_oid = if (kind == .authroot) ctl.authroot_usage else ctl.disallowed_usage,
            .entries = &.{.{ .identifier = &identifier, .attributes = &attributes }},
        });
        defer allocator.free(encoded);
        var snapshot = platform.Snapshot.init(allocator, .{});
        defer snapshot.deinit();
        const native = try snapshot.add("certificate", true);
        snapshot.entries.items[native].windows = .{ .disallow_at = 1_900_000_000 };
        try ctl.append(&snapshot, kind, encoded);
        const actual = snapshot.fingerprint_lists.items[0].entries[0].policy;
        try std.testing.expect(actual.unsupported);
        try std.testing.expectEqual(@as(u2, if (kind == .authroot) 1 else 0), actual.roles);
        try std.testing.expectEqual(@as(u2, 2), actual.denied_roles);
        try std.testing.expectEqual(@as(?i64, 1_800_000_000), actual.disallow_at);
        try std.testing.expectEqual(@as(?i64, 1_900_000_000), snapshot.entries.items[native].windows.?.disallow_at);
        var context: u8 = 0;
        const hasher = digest.MetadataDigest{ .context = &context, .digest_fn = hash, .options = .{ .allow_sha1_identifiers = true } };
        for ([_]@import("trust.zig").PeerRole{ .server, .client }) |role| {
            for ([_]i64{ 1_799_999_999, 1_800_000_000, 1_800_000_001 }) |now| {
                var request_use = use;
                request_use.role = role;
                request_use.now_seconds = now;
                request_use.custom_anchor = true;
                try std.testing.expectEqual(platform.Decision.deny, try snapshot.check("certificate", request_use, hasher, allocator));
            }
        }
        const Test = struct {
            fn run(backing: std.mem.Allocator, bytes: []const u8, list_kind: platform.FingerprintList.Kind) !void {
                var copied = platform.Snapshot.init(backing, .{});
                defer copied.deinit();
                try ctl.append(&copied, list_kind, bytes);
                try std.testing.expect(copied.fingerprint_lists.items[0].entries[0].policy.unsupported);
            }
        };
        try std.testing.checkAllAllocationFailures(allocator, Test.run, .{ encoded, kind });
    }
}

test "CTL malformed time encodings still fail atomically" {
    for ([_]platform.FingerprintList.Kind{ .authroot, .disallowed }) |kind| {
        for ([_]u32{ 104, 128 }) |id| {
            for ([_][]const u8{
                "",
                "\x00" ** 7,
                "\x00" ** 9,
                "250101000000Z",
                "\x17\x0d250101000000Z",
                "\x18\x0f20250101000000Z",
                "\x04\x08abcdefgh",
                "\x04\x08abcdefgh\x00",
            }) |value| {
                if (id == 104 and value.len == 0) continue;
                const encoded = try fixtures.content(allocator, .{
                    .usage_oid = if (kind == .authroot) ctl.authroot_usage else ctl.disallowed_usage,
                    .entries = &.{
                        .{ .identifier = &identifier },
                        .{ .identifier = &identifier, .attributes = &.{.{ .id = id, .value = value }} },
                    },
                });
                defer allocator.free(encoded);
                var snapshot = platform.Snapshot.init(allocator, .{});
                defer snapshot.deinit();
                try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, kind, encoded));
                try std.testing.expectEqual(@as(usize, 0), snapshot.fingerprint_lists.items.len);
                try std.testing.expectEqual(@as(usize, 0), snapshot.fingerprint_entries);
            }
        }
    }
}

test "CTL rejects MD5 and alternate unknown identifier forms before committing data" {
    const md5 = try fixtures.content(allocator, .{
        .algorithm_oid = "\x2a\x86\x48\x86\xf7\x0d\x02\x05",
        .entries = &.{.{ .identifier = &@as([16]u8, @splat(1)) }},
    });
    defer allocator.free(md5);
    var snapshot = platform.Snapshot.init(allocator, .{});
    defer snapshot.deinit();
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, .authroot, md5));
    for ([_]u32{ 4, 15, 25, 999 }) |id| {
        const encoded = try fixtures.content(allocator, .{ .entries = &.{.{
            .identifier = &identifier,
            .attributes = &.{.{ .id = id, .value = &identifier }},
        }} });
        defer allocator.free(encoded);
        try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, .authroot, encoded));
    }
    try std.testing.expectEqual(@as(usize, 0), snapshot.fingerprint_lists.items.len);
}

test "CTL duplicate properties unknown extensions and truncated DER fail atomically" {
    var snapshot = platform.Snapshot.init(allocator, .{});
    defer snapshot.deinit();
    const duplicate = try fixtures.content(allocator, .{ .entries = &.{.{
        .identifier = &identifier,
        .attributes = &.{ .{ .id = 9, .value = server_eku }, .{ .id = 9, .value = client_eku } },
    }} });
    defer allocator.free(duplicate);
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, .authroot, duplicate));
    const extension = try fixtures.content(allocator, .{ .extra_tail = "\xa0\x02\x30\x00" });
    defer allocator.free(extension);
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, .authroot, extension));
    const late_failure = try fixtures.content(allocator, .{ .entries = &.{
        .{ .identifier = &identifier },
        .{ .identifier = &identifier, .attributes = &.{.{ .id = 999, .value = "unsupported" }} },
    } });
    defer allocator.free(late_failure);
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, .authroot, late_failure));
    try std.testing.expectEqual(@as(usize, 0), snapshot.fingerprint_lists.items.len);
    const valid = try fixtures.content(allocator, .{ .entries = &.{.{ .identifier = &identifier }} });
    defer allocator.free(valid);
    for (0..valid.len) |length| {
        if (ctl.append(&snapshot, .authroot, valid[0..length])) |_| {
            return error.TestUnexpectedResult;
        } else |err| {
            try std.testing.expect(err == error.TlsMalformedCertificate or err == error.TlsTrustStoreLoadFailed);
        }
        try std.testing.expectEqual(@as(usize, 0), snapshot.fingerprint_lists.items.len);
    }
}

test "CTL tail diagnostics do not authorize recognized or critical global extensions" {
    const sorted = "\xa0\x14\x30\x12\x30\x10\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x0a\x01\x01\x04\x02\x30\x00";
    const critical_unknown = "\xa0\x16\x30\x14\x30\x12\x06\x03\x2a\x03\x04\x01\x01\xff\x04\x08\x30\x06\x02\x01\x01\x04\x01x";
    for ([_]platform.FingerprintList.Kind{ .authroot, .disallowed }) |kind| {
        for ([_][]const u8{ sorted, critical_unknown, "\xa0\x80\x00\x00", "\x02\x01\x01" }) |tail| {
            const encoded = try fixtures.content(allocator, .{
                .usage_oid = if (kind == .authroot) ctl.authroot_usage else ctl.disallowed_usage,
                .entries = &.{.{ .identifier = &identifier, .attributes = &.{.{ .id = 104, .value = "" }} }},
                .extra_tail = tail,
            });
            defer allocator.free(encoded);
            var snapshot = platform.Snapshot.init(allocator, .{});
            defer snapshot.deinit();
            try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, kind, encoded));
            try std.testing.expectEqual(@as(usize, 0), snapshot.fingerprint_lists.items.len);
            try std.testing.expectEqual(@as(usize, 0), snapshot.fingerprint_entries);
        }
    }
}

test "CTL input ownership allocation and record bounds are finite" {
    const encoded = try fixtures.content(allocator, .{ .entries = &.{.{ .identifier = &identifier }} });
    defer allocator.free(encoded);
    const Test = struct {
        fn run(backing: std.mem.Allocator, bytes: []const u8) !void {
            var snapshot = platform.Snapshot.init(backing, .{});
            defer snapshot.deinit();
            try ctl.append(&snapshot, .authroot, bytes);
            try std.testing.expectEqualSlices(u8, &identifier, snapshot.fingerprint_lists.items[0].entries[0].identifier[0..20]);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Test.run, .{encoded});
    for ([_]platform.Limits{ .{ .max_ctl_bytes = 1 }, .{ .max_fingerprint_entries = 0 }, .{ .max_fingerprint_lists = 0 } }) |limits| {
        var snapshot = platform.Snapshot.init(allocator, limits);
        defer snapshot.deinit();
        try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, .authroot, encoded));
    }
    var snapshot = platform.Snapshot.init(allocator, .{});
    defer snapshot.deinit();
    const copied = try allocator.dupe(u8, encoded);
    defer allocator.free(copied);
    try ctl.append(&snapshot, .authroot, copied);
    @memset(copied, 0);
    try std.testing.expectEqualSlices(u8, &identifier, snapshot.fingerprint_lists.items[0].entries[0].identifier[0..20]);
}

test "program-root membership requires current AuthRoot metadata and never overrides distrust" {
    var snapshot = platform.Snapshot.init(allocator, .{});
    defer snapshot.deinit();
    const index = try snapshot.add("program certificate", true);
    snapshot.entries.items[index].authroot_program = true;
    var request_use = use;
    request_use.anchor = true;
    var context: u8 = 0;
    const hasher = digest.MetadataDigest{ .context = &context, .digest_fn = hash, .options = .{ .allow_sha1_identifiers = true } };
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.check("program certificate", request_use, hasher, allocator));
    const encoded = try fixtures.content(allocator, .{ .entries = &.{.{ .identifier = &identifier }} });
    defer allocator.free(encoded);
    try ctl.append(&snapshot, .authroot, encoded);
    try std.testing.expectEqual(platform.Decision.anchor, try snapshot.check("program certificate", request_use, hasher, allocator));
    request_use.now_seconds = 2_100_000_000;
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.check("program certificate", request_use, hasher, allocator));
    request_use.now_seconds = use.now_seconds;
    const denied = try fixtures.content(allocator, .{ .usage_oid = ctl.disallowed_usage, .entries = &.{.{ .identifier = &identifier }} });
    defer allocator.free(denied);
    try ctl.append(&snapshot, .disallowed, denied);
    request_use.custom_anchor = true;
    try std.testing.expectEqual(platform.Decision.deny, try snapshot.check("program certificate", request_use, hasher, allocator));
}
