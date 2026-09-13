const std = @import("std");
const extensions = @import("windows_ctl_extensions.zig");
const ctl = @import("windows_ctl.zig");
const fixture = @import("ctl_fixtures.zig");
const certificates = @import("trust_fixtures.zig");
const x509 = @import("x509_policy.zig");
const platform = @import("platform_trust.zig");
const allocator = std.testing.allocator;
const header = "\x30\x09\x02\x01\x00\x02\x01\x00\x02\x01\x00";
const identifier: [20]u8 = @splat(1);

fn catalog(backing: std.mem.Allocator, parameters: []const u8, keys: []const []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const a = arena.allocator();
    const value = try fixture.join(a, &.{ parameters, try fixture.join(a, keys) });
    return backing.dupe(u8, try fixture.element(a, 0x30, value));
}

fn extension(backing: std.mem.Allocator, oid: []const u8, critical: ?bool, value: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const a = arena.allocator();
    const content = try fixture.join(a, &.{
        try fixture.element(a, 0x06, oid),
        if (critical) |flag| (if (flag) "\x01\x01\xff" else "\x01\x01\x00") else "",
        try fixture.element(a, 0x04, value),
    });
    return backing.dupe(u8, try fixture.element(a, 0x30, content));
}

fn tail(backing: std.mem.Allocator, entries: []const []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const a = arena.allocator();
    const content = try fixture.element(a, 0x30, try fixture.join(a, entries));
    return backing.dupe(u8, try fixture.element(a, 0xa0, content));
}

fn catalogTail(backing: std.mem.Allocator, value: []const u8) ![]u8 {
    const encoded = try extension(backing, extensions.cert_log_list_oid, null, value);
    defer backing.free(encoded);
    return tail(backing, &.{encoded});
}

test "noncritical CT catalog has an integer header and SPKIs without adding anchors" {
    var chain = try certificates.Chain.init(allocator, .ecdsa_p256);
    defer chain.deinit();
    const spki = (try x509.parse(chain.root)).spki;
    const keys = [_][]const u8{spki} ** 49;
    const value = try catalog(allocator, header, &keys);
    defer allocator.free(value);
    // Same public schema dimensions as the observed native catalog, not
    // native log keys or an inference about the parameter values.
    try std.testing.expectEqual(@as(usize, 4474), value.len);
    const encoded_tail = try catalogTail(allocator, value);
    defer allocator.free(encoded_tail);
    try extensions.validate(encoded_tail, 64 * 1024);
    const encoded = try fixture.content(allocator, .{
        .entries = &.{.{ .identifier = &identifier, .attributes = &.{.{ .id = 104, .value = "" }} }},
        .extra_tail = encoded_tail,
    });
    defer allocator.free(encoded);
    var snapshot = platform.Snapshot.init(allocator, .{});
    defer snapshot.deinit();
    try ctl.append(&snapshot, .authroot, encoded);
    try std.testing.expectEqual(@as(usize, 0), snapshot.entries.items.len);
    try std.testing.expectEqual(@as(usize, 1), snapshot.fingerprint_entries);
    try std.testing.expect(snapshot.fingerprint_lists.items[0].entries[0].policy.unsupported);

    const Test = struct {
        fn run(backing: std.mem.Allocator, bytes: []const u8) !void {
            var owned = platform.Snapshot.init(backing, .{});
            defer owned.deinit();
            ctl.append(&owned, .authroot, bytes) catch |err| {
                try std.testing.expectEqual(@as(usize, 0), owned.fingerprint_lists.items.len);
                try std.testing.expectEqual(@as(usize, 0), owned.fingerprint_entries);
                return err;
            };
            try std.testing.expect(owned.fingerprint_lists.items[0].entries[0].policy.unsupported);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Test.run, .{encoded});
    @memset(encoded, 0);
    try std.testing.expect(snapshot.fingerprint_lists.items[0].entries[0].policy.unsupported);
}

test "catalog parameters are bounded framing not permissions or guessed versions" {
    for ([_][]const u8{
        header,
        "\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
        "\x30\x0d\x02\x05\x00\xff\xff\xff\xff\x02\x01\x00\x02\x01\x00",
    }) |parameters| {
        const value = try catalog(allocator, parameters, &.{});
        defer allocator.free(value);
        const encoded = try catalogTail(allocator, value);
        defer allocator.free(encoded);
        try extensions.validate(encoded, 1024);
    }
    for ([_][]const u8{
        "",
        "\x30\x00",
        "\x30\x06\x02\x01\x00\x02\x01\x00",
        "\x30\x0c\x02\x01\x00\x02\x01\x00\x02\x01\x00\x02\x01\x00",
        "\x30\x09\x02\x01\xff\x02\x01\x00\x02\x01\x00",
        "\x30\x0a\x02\x02\x00\x01\x02\x01\x00\x02\x01\x00",
        "\x30\x0e\x02\x06\x00\x01\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00",
    }) |parameters| {
        const value = try catalog(allocator, parameters, &.{});
        defer allocator.free(value);
        const encoded = try catalogTail(allocator, value);
        defer allocator.free(encoded);
        try std.testing.expectError(error.TlsTrustStoreLoadFailed, extensions.validate(encoded, 1024));
    }
}

test "unknown critical duplicate and trailing global data fail atomically" {
    const value = try catalog(allocator, header, &.{});
    defer allocator.free(value);
    const known = try extension(allocator, extensions.cert_log_list_oid, null, value);
    defer allocator.free(known);
    const unknown = try extension(allocator, "\x2a\x03\x04", null, value);
    defer allocator.free(unknown);
    const critical = try extension(allocator, extensions.cert_log_list_oid, true, value);
    defer allocator.free(critical);
    const explicit_false = try extension(allocator, extensions.cert_log_list_oid, false, value);
    defer allocator.free(explicit_false);
    for ([_][]const []const u8{ &.{unknown}, &.{critical}, &.{explicit_false}, &.{ known, known }, &.{ known, unknown }, &.{} }) |entries| {
        const encoded_tail = try tail(allocator, entries);
        defer allocator.free(encoded_tail);
        const encoded = try fixture.content(allocator, .{
            .entries = &.{.{ .identifier = &identifier }},
            .extra_tail = encoded_tail,
        });
        defer allocator.free(encoded);
        var snapshot = platform.Snapshot.init(allocator, .{});
        defer snapshot.deinit();
        try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, .authroot, encoded));
        try std.testing.expectEqual(@as(usize, 0), snapshot.fingerprint_lists.items.len);
        try std.testing.expectEqual(@as(usize, 0), snapshot.fingerprint_entries);
    }
    const encoded = try tail(allocator, &.{known});
    defer allocator.free(encoded);
    const disallowed = try fixture.content(allocator, .{ .usage_oid = ctl.disallowed_usage, .extra_tail = encoded });
    defer allocator.free(disallowed);
    var snapshot = platform.Snapshot.init(allocator, .{});
    defer snapshot.deinit();
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, .disallowed, disallowed));
    const extra = try fixture.join(allocator, &.{ encoded, "\x00" });
    defer allocator.free(extra);
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, extensions.validate(extra, 1024));
    for (0..encoded.len) |length| {
        try std.testing.expectError(error.TlsTrustStoreLoadFailed, extensions.validate(encoded[0..length], 1024));
    }
}

test "catalog rejects malformed SPKIs unsupported key profiles and excessive input" {
    var chain = try certificates.Chain.init(allocator, .ecdsa_p256);
    defer chain.deinit();
    const spki = (try x509.parse(chain.root)).spki;
    for (0..spki.len) |length| {
        const value = try catalog(allocator, header, &.{spki[0..length]});
        defer allocator.free(value);
        const encoded = try catalogTail(allocator, value);
        defer allocator.free(encoded);
        if (length == 0) {
            try extensions.validate(encoded, 64 * 1024);
        } else {
            try std.testing.expectError(error.TlsTrustStoreLoadFailed, extensions.validate(encoded, 64 * 1024));
        }
    }
    var unsupported = try certificates.Chain.init(allocator, .ed25519);
    defer unsupported.deinit();
    const wrong_key = try catalog(allocator, header, &.{(try x509.parse(unsupported.root)).spki});
    defer allocator.free(wrong_key);
    const wrong_tail = try catalogTail(allocator, wrong_key);
    defer allocator.free(wrong_tail);
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, extensions.validate(wrong_tail, 64 * 1024));
    const keys = [_][]const u8{spki} ** (extensions.max_log_keys + 1);
    const too_many = try catalog(allocator, header, &keys);
    defer allocator.free(too_many);
    const too_many_tail = try catalogTail(allocator, too_many);
    defer allocator.free(too_many_tail);
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, extensions.validate(too_many_tail, 64 * 1024));
    const at_limit = try catalog(allocator, header, keys[0..extensions.max_log_keys]);
    defer allocator.free(at_limit);
    const at_limit_tail = try catalogTail(allocator, at_limit);
    defer allocator.free(at_limit_tail);
    try extensions.validate(at_limit_tail, 64 * 1024);
    const single = try catalog(allocator, header, &.{spki});
    defer allocator.free(single);
    const single_tail = try catalogTail(allocator, single);
    defer allocator.free(single_tail);
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, extensions.validate(single_tail, single.len - 1));
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, extensions.validate(single_tail, 0));

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const oversized_key = try fixture.element(a, 0x30, &(@as([extensions.max_log_key_bytes]u8, @splat(0))));
    const oversized = try catalog(a, header, &.{oversized_key});
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, extensions.validate(try catalogTail(a, oversized), 64 * 1024));
    const bad_point = try a.dupe(u8, spki);
    bad_point[bad_point.len - 65] = 2;
    const malformed = try catalog(a, header, &.{bad_point});
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, extensions.validate(try catalogTail(a, malformed), 64 * 1024));
    const trailing = try catalog(a, header, &.{ spki, "\x05\x00" });
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, extensions.validate(try catalogTail(a, trailing), 64 * 1024));
}

test "catalog consumes each nested envelope and preserves previously accepted lists on failure" {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const value = try catalog(a, header, &.{});
    const known = try extension(a, extensions.cert_log_list_oid, null, value);
    const malformed_extension = try fixture.element(a, 0x30, try fixture.join(a, &.{
        try fixture.element(a, 0x06, extensions.cert_log_list_oid),
        try fixture.element(a, 0x04, value),
        "\x05\x00",
    }));
    const malformed_wrapper = try fixture.element(a, 0xa0, try fixture.join(a, &.{
        try fixture.element(a, 0x30, known),
        "\x05\x00",
    }));
    const malformed_catalog = try catalogTail(a, try fixture.join(a, &.{ value, "\x05\x00" }));
    const accepted = try fixture.content(a, .{ .entries = &.{.{ .identifier = &identifier }} });
    for ([_][]const u8{ try tail(a, &.{malformed_extension}), malformed_wrapper, malformed_catalog }) |bad_tail| {
        var snapshot = platform.Snapshot.init(allocator, .{});
        defer snapshot.deinit();
        try ctl.append(&snapshot, .authroot, accepted);
        const rejected = try fixture.content(a, .{ .entries = &.{.{ .identifier = &identifier }}, .extra_tail = bad_tail });
        try std.testing.expectError(error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, .authroot, rejected));
        try std.testing.expectEqual(@as(usize, 1), snapshot.fingerprint_lists.items.len);
        try std.testing.expectEqual(@as(usize, 1), snapshot.fingerprint_entries);
        try std.testing.expect(!snapshot.fingerprint_lists.items[0].entries[0].policy.unsupported);
    }
}

test "catalog validates bounded RSA and P384 SPKI framing without using the keys" {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rsa_key = try fixture.element(a, 0x30, try fixture.join(a, &.{
        try fixture.element(a, 0x02, "\x00\x80" ++ ("\x01" ** 255)),
        "\x02\x03\x01\x00\x01",
    }));
    const rsa_spki = try fixture.element(a, 0x30, try fixture.join(a, &.{
        "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00",
        try fixture.element(a, 0x03, try fixture.join(a, &.{ "\x00", rsa_key })),
    }));
    const key = try std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair.generateDeterministic(@splat(0x31));
    const p384_spki = "\x30\x76\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x22\x03\x62\x00".* ++
        key.public_key.toUncompressedSec1();
    const value = try catalog(a, header, &.{ rsa_spki, &p384_spki });
    try extensions.validate(try catalogTail(a, value), 64 * 1024);
}

test "canonical path cannot use catalog log keys as certificate anchors" {
    const policy = @import("standard_trust.zig");
    const StandardProvider = @import("crypto/standard.zig").StandardProvider;
    const CryptoCertificateVerifier = @import("cert_crypto.zig").CryptoCertificateVerifier;
    var chain = try certificates.Chain.init(allocator, .ecdsa_p256);
    defer chain.deinit();
    const unrelated_key = try certificates.Key.init(.ed25519, 0x42);
    const unrelated_root = try certificates.certificate(allocator, unrelated_key, unrelated_key, .{
        .subject = "Unrelated root",
        .issuer = "Unrelated root",
        .is_ca = true,
        .key_usage = "\x01\x06",
        .san = null,
    });
    defer allocator.free(unrelated_root);
    var owner = try policy.TrustContext.init(allocator, std.testing.io, .{
        .source = .{ .custom_only = .{ .der_certificates = &.{unrelated_root} } },
    });
    defer owner.deinit();
    owner.platform_snapshot = platform.Snapshot.init(allocator, .{});
    const value = try catalog(allocator, header, &.{(try x509.parse(chain.root)).spki});
    defer allocator.free(value);
    const encoded_tail = try catalogTail(allocator, value);
    defer allocator.free(encoded_tail);
    const encoded = try fixture.content(allocator, .{
        .algorithm_oid = "\x60\x86\x48\x01\x65\x03\x04\x02\x01",
        .extra_tail = encoded_tail,
    });
    defer allocator.free(encoded);
    try ctl.append(&owner.platform_snapshot.?, .authroot, encoded);
    try std.testing.expectEqual(@as(usize, 1), owner.anchorCount());
    try std.testing.expectEqual(@as(usize, 0), owner.platform_snapshot.?.entries.items.len);
    var standard = StandardProvider.init(std.testing.io, allocator);
    var adapter = CryptoCertificateVerifier.init(standard.provider());
    var binding = try owner.bind(&adapter, .{});
    try std.testing.expectError(error.TlsUnknownCa, binding.provider().verifyPeer(.{
        .role = .server,
        .chain_der = &.{ chain.leaf, chain.intermediate },
        .expected_identity = .{ .dns_name = "api.example.test" },
        .now_seconds = 1_800_000_000,
        .signature_verifier = binding.signatureVerifier(),
        .scratch_allocator = allocator,
    }));
}

test "catalog preserves freshness purpose membership provenance and per-subject exclusions" {
    const digest = @import("metadata_digest.zig");
    const crypto = @import("crypto/provider.zig");
    const Test = struct {
        fn hash(_: *anyopaque, _: std.mem.Allocator, _: crypto.HashAlgorithm, input: []const u8, output: []u8) crypto.ProviderError!void {
            @memset(output, if (std.mem.eql(u8, input, "listed")) @as(u8, 1) else 2);
        }
    };
    const value = try catalog(allocator, header, &.{});
    defer allocator.free(value);
    const encoded_tail = try catalogTail(allocator, value);
    defer allocator.free(encoded_tail);
    for ([_]bool{ false, true }) |unsupported| {
        const attributes = [_]fixture.Attribute{
            .{ .id = 9, .value = "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01" },
            .{ .id = 104, .value = "" },
        };
        const encoded = try fixture.content(allocator, .{
            .entries = &.{.{ .identifier = &identifier, .attributes = attributes[0..@as(usize, if (unsupported) 2 else 1)] }},
            .extra_tail = encoded_tail,
        });
        defer allocator.free(encoded);
        var snapshot = platform.Snapshot.init(allocator, .{});
        defer snapshot.deinit();
        for ([_][]const u8{ "listed", "unlisted" }) |certificate| {
            const index = try snapshot.add(certificate, true);
            snapshot.entries.items[index].authroot_program = true;
            snapshot.entries.items[index].windows = .{};
        }
        try ctl.append(&snapshot, .authroot, encoded);
        var context: u8 = 0;
        const hasher = digest.MetadataDigest{ .context = &context, .digest_fn = Test.hash, .options = .{ .allow_sha1_identifiers = true } };
        var use: platform.Use = .{ .role = .server, .identity = null, .now_seconds = 1_800_000_000, .issuer = true, .self_issued = true, .anchor = true };
        try std.testing.expectEqual(if (unsupported) platform.Decision.deny else .anchor, try snapshot.check("listed", use, hasher, allocator));
        try std.testing.expectEqual(platform.Decision.deny, try snapshot.check("unlisted", use, hasher, allocator));
        use.role = .client;
        try std.testing.expectEqual(platform.Decision.deny, try snapshot.check("listed", use, hasher, allocator));
        use.role = .server;
        use.custom_anchor = true;
        try std.testing.expectEqual(platform.Decision.anchor, try snapshot.check("unlisted", use, hasher, allocator));
        try std.testing.expectEqual(if (unsupported) platform.Decision.deny else .anchor, try snapshot.check("listed", use, hasher, allocator));
        for ([_]i64{ 1_700_000_000, 2_100_000_000 }) |outside_list_time| {
            use.now_seconds = outside_list_time;
            try std.testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.check("listed", use, hasher, allocator));
        }
        use.now_seconds = 1_800_000_000;
        snapshot.entries.items[1].windows.?.disallow_at = use.now_seconds;
        try std.testing.expectEqual(platform.Decision.deny, try snapshot.check("unlisted", use, hasher, allocator));
        try std.testing.expectEqual(@as(usize, 2), snapshot.entries.items.len);
    }
}
