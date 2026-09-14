//! Hermetic metadata-only tests. Algorithm-override fixtures do not prove
//! signature authentication under their advertised algorithms.
const std = @import("std");
const testing = std.testing;
const a = testing.allocator;
const x509 = @import("x509_policy.zig");
const disallowed = @import("windows_disallowed.zig");
const platform = @import("platform_trust.zig");
const ctl = @import("windows_ctl.zig");
const fixtures = @import("trust_fixtures.zig");
const ctlf = @import("ctl_fixtures.zig");
const p = @import("crypto/provider.zig");
const Standard = @import("crypto/standard.zig").StandardProvider;
const Adapter = @import("cert_crypto.zig").CryptoCertificateVerifier;
const digest = @import("metadata_digest.zig");
const both: digest.Options = .{ .allow_sha1_identifiers = true, .allow_md5_identifiers = true };
const use: platform.Use = .{ .role = .server, .identity = null, .now_seconds = 1_800_000_000, .issuer = false, .self_issued = false };
const rsa_prefix = "\x2a\x86\x48\x86\xf7\x0d\x01\x01";
const ecdsa384 = "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03";
const md5_rsa = "\x30\x0d\x06\x09" ++ rsa_prefix ++ "\x04\x05\x00";
const pss_default = "\x30\x0d\x06\x09" ++ rsa_prefix ++ "\x0a\x30\x00";

fn certificate(algorithm_override: ?[]const u8, serial: u8) ![]u8 {
    const key = try fixtures.Key.init(.ecdsa_p256, 42);
    return fixtures.certificate(a, key, key, .{
        .subject = "metadata subject",
        .issuer = "metadata issuer",
        .serial = serial,
        .signature_algorithm_override = algorithm_override,
    });
}

fn algorithm(allocator: std.mem.Allocator, oid: []const u8, parameters: []const u8) ![]const u8 {
    return ctlf.element(allocator, 0x30, try ctlf.join(allocator, &.{
        try ctlf.element(allocator, 0x06, oid), parameters,
    }));
}

fn pss(allocator: std.mem.Allocator, hash: u8, mgf_hash: u8, salt: u8, tail: []const u8) ![]const u8 {
    const prefix = "\x60\x86\x48\x01\x65\x03\x04\x02";
    const hash_id = try algorithm(allocator, try ctlf.join(allocator, &.{ prefix, &.{hash} }), "\x05\x00");
    const mgf_id = try algorithm(allocator, try ctlf.join(allocator, &.{ prefix, &.{mgf_hash} }), "\x05\x00");
    return algorithm(allocator, rsa_prefix ++ "\x0a", try ctlf.element(allocator, 0x30, try ctlf.join(allocator, &.{
        try ctlf.element(allocator, 0xa0, hash_id),
        try ctlf.element(allocator, 0xa1, try algorithm(allocator, rsa_prefix ++ "\x08", mgf_id)),
        try ctlf.element(allocator, 0xa2, try ctlf.element(allocator, 0x02, &.{salt})),
        tail,
    })));
}

fn add(snapshot: *platform.Snapshot, entries: []const ctlf.Entry) !void {
    const encoded = try ctlf.content(snapshot.allocator, .{
        .usage_oid = ctl.disallowed_usage,
        .algorithm_oid = ctl.disallowed_hash,
        .algorithm_parameters = "\x05\x00",
        .entries = entries,
    });
    defer snapshot.allocator.free(encoded);
    try ctl.append(snapshot, .disallowed, encoded);
}

fn reference(algorithm_value: p.HashAlgorithm, bytes: []const u8, output: []u8) !void {
    var standard = Standard.initWithOptions(testing.io, a, .{ .allow_md5_identifier_hash = true });
    var adapter = Adapter.init(standard.provider());
    try adapter.metadataHasher(both).hash(a, algorithm_value, bytes, output);
}

const Spy = struct {
    selected: p.CryptoProvider,
    inputs: disallowed.Inputs,
    calls: usize = 0,
    key_calls: usize = 0,
    tbs_calls: usize = 0,
    fail_at: usize = 0,
    failure: p.ProviderError = error.InternalError,

    fn hasher(self: *Spy) digest.MetadataDigest {
        return .{ .context = self, .digest_fn = hash, .options = both };
    }

    fn hash(context: *anyopaque, allocator: std.mem.Allocator, hash_algorithm: p.HashAlgorithm, input: []const u8, output: []u8) p.ProviderError!void {
        const self: *Spy = @ptrCast(@alignCast(context));
        self.calls += 1;
        if (std.mem.eql(u8, input, self.inputs.public_key_bits) and hash_algorithm == .md5)
            self.key_calls += 1
        else if (std.mem.eql(u8, input, self.inputs.tbs_der) and hash_algorithm == self.inputs.signature_hash)
            self.tbs_calls += 1
        else
            return error.InvalidInput;
        if (self.calls == self.fail_at) {
            output[0] = 0xa5;
            return self.failure;
        }
        var handle = try self.selected.hashCreate(allocator, hash_algorithm);
        defer handle.deinit();
        try handle.update(input);
        try handle.snapshot(output);
    }
};

test "Disallowed owns exact mixed identifiers without width classification or anchor promotion" {
    const lengths = [_]usize{ 64, 16, 48, 32, 20 };
    var bytes: [64]u8 = @splat(0x42);
    var entries: [lengths.len]ctlf.Entry = undefined;
    for (lengths, &entries) |length, *entry| entry.* = .{ .identifier = bytes[0..length] };
    var snapshot = platform.Snapshot.init(a, .{});
    defer snapshot.deinit();
    try add(&snapshot, &entries);
    @memset(&bytes, 0xff);
    try testing.expectEqual(@as(usize, 0), snapshot.entries.items.len);
    const list = snapshot.fingerprint_lists.items[0];
    try testing.expectEqual(platform.FingerprintList.Identity.windows_disallowed, list.identity);
    try testing.expectEqual(@as(?p.HashAlgorithm, null), list.algorithm);
    for (list.entries, [_]usize{ 16, 20, 32, 48, 64 }) |entry, length| {
        try testing.expectEqual(length, entry.bytes().len);
        try testing.expect(std.mem.allEqual(u8, entry.bytes(), 0x42));
    }
}

test "Disallowed rejects wrong lengths unknown selectors parameters attributes and global data atomically" {
    var snapshot = platform.Snapshot.init(a, .{});
    defer snapshot.deinit();
    try add(&snapshot, &.{.{ .identifier = "\x42" ** 16 }});
    for ([_]usize{ 0, 1, 15, 17, 28, 31, 33, 47, 49, 65 }) |length| {
        const bytes: [65]u8 = @splat(0x42);
        try testing.expectError(error.TlsTrustStoreLoadFailed, add(&snapshot, &.{
            .{ .identifier = "\x42" ** 16 }, .{ .identifier = bytes[0..length] },
        }));
        try testing.expectEqual(@as(usize, 1), snapshot.fingerprint_lists.items.len);
        try testing.expectEqual(@as(usize, 1), snapshot.fingerprint_entries);
    }
    const invalid = [_]ctlf.Options{
        .{ .algorithm_oid = ctl.disallowed_hash },
        .{ .usage_oid = ctl.disallowed_usage, .algorithm_oid = ctl.disallowed_hash, .algorithm_parameters = "\x05\x01\x00" },
        .{ .usage_oid = ctl.disallowed_usage, .algorithm_oid = ctl.disallowed_hash, .algorithm_parameters = "\x04\x00" },
        .{ .usage_oid = ctl.disallowed_usage, .algorithm_oid = "\x2b\x06\x01\x04\x01\x82\x37\x0a\x0b\x19" },
        .{ .usage_oid = ctl.disallowed_usage, .algorithm_oid = "\x2a\x86\x48\x86\xf7\x0d\x02\x05" },
        .{ .usage_oid = ctl.disallowed_usage, .algorithm_oid = ctl.disallowed_hash, .extra_tail = "\xa0\x02\x30\x00" },
        .{ .usage_oid = ctl.disallowed_usage, .algorithm_oid = ctl.disallowed_hash, .entries = &.{
            .{ .identifier = "\x42" ** 16, .attributes = &.{.{ .id = 25, .value = "\x42" ** 16 }} },
        } },
    };
    for (invalid, 0..) |options, index| {
        const encoded = try ctlf.content(a, options);
        defer a.free(encoded);
        try testing.expectError(if (index == 2) error.TlsMalformedCertificate else error.TlsTrustStoreLoadFailed, ctl.append(&snapshot, if (index == 0) .authroot else .disallowed, encoded));
        try testing.expectEqual(@as(usize, 1), snapshot.fingerprint_lists.items.len);
        try testing.expectEqual(@as(usize, 1), snapshot.fingerprint_entries);
    }
}

test "Disallowed selects documented TBS algorithms without authorizing their signatures" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    const cases = [_]struct { encoded: ?[]const u8, hash: p.HashAlgorithm }{
        .{ .encoded = null, .hash = .sha256 },
        .{ .encoded = ecdsa384, .hash = .sha384 },
        .{ .encoded = md5_rsa, .hash = .md5 },
        .{ .encoded = try algorithm(scratch, rsa_prefix ++ "\x05", "\x05\x00"), .hash = .sha1 },
        .{ .encoded = try algorithm(scratch, rsa_prefix ++ "\x0b", "\x05\x00"), .hash = .sha256 },
        .{ .encoded = try algorithm(scratch, rsa_prefix ++ "\x0c", "\x05\x00"), .hash = .sha384 },
        .{ .encoded = try algorithm(scratch, rsa_prefix ++ "\x0d", "\x05\x00"), .hash = .sha512 },
        .{ .encoded = try algorithm(scratch, rsa_prefix ++ "\x0d", ""), .hash = .sha512 },
        .{ .encoded = pss_default, .hash = .sha1 },
        .{ .encoded = try pss(scratch, 1, 1, 32, ""), .hash = .sha256 },
        .{ .encoded = try pss(scratch, 2, 2, 48, ""), .hash = .sha384 },
        .{ .encoded = try pss(scratch, 3, 3, 64, ""), .hash = .sha512 },
    };
    for (cases) |case| {
        const der = try certificate(case.encoded, 1);
        defer a.free(der);
        const inputs = try disallowed.parse(der);
        const parsed = try x509.parse(der);
        try testing.expectEqual(case.hash, inputs.signature_hash);
        try testing.expectEqualSlices(u8, parsed.tbs, inputs.tbs_der);
        var spki_outer = x509.Reader.init(parsed.spki);
        var spki = x509.Reader.init((try spki_outer.take(0x30)).content);
        _ = try spki.take(0x30);
        const bits = (try spki.take(0x03)).content;
        try testing.expectEqualSlices(u8, bits[1..], inputs.public_key_bits);
        var identifier: [64]u8 = undefined;
        try reference(case.hash, parsed.tbs, identifier[0..case.hash.digestLength()]);
        var snapshot = platform.Snapshot.init(a, .{});
        defer snapshot.deinit();
        try add(&snapshot, &.{.{ .identifier = identifier[0..case.hash.digestLength()] }});
        var standard = Standard.initWithOptions(testing.io, a, .{ .allow_md5_identifier_hash = true });
        var spy = Spy{ .selected = standard.provider(), .inputs = inputs };
        try testing.expectEqual(platform.Decision.deny, try snapshot.check(der, use, spy.hasher(), a));
        try testing.expectEqual(@as(usize, 1), spy.key_calls);
        try testing.expectEqual(@as(usize, 1), spy.tbs_calls);
    }
}

test "Disallowed rejects unsupported PSS mappings parameters inner outer mismatch and key framing" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    const invalid = [_][]const u8{
        "\x30\x05\x06\x03\x2b\x65\x70",
        try algorithm(scratch, "\x2a\x03\x04", ""),
        try algorithm(scratch, rsa_prefix ++ "\x0a", ""),
        try algorithm(scratch, rsa_prefix ++ "\x0a", "\x05\x00"),
        try algorithm(scratch, rsa_prefix ++ "\x04", "\x04\x00"),
        try algorithm(scratch, rsa_prefix ++ "\x04", ""),
        try algorithm(scratch, rsa_prefix ++ "\x05", ""),
        try algorithm(scratch, "\x2a\x86\x48\xce\x3d\x04\x03\x02", "\x05\x00"),
        try pss(scratch, 1, 2, 32, ""),
        try pss(scratch, 1, 1, 20, ""),
        try pss(scratch, 1, 1, 32, "\xa3\x03\x02\x01\x01"),
        try pss(scratch, 1, 1, 32, "\xa2\x03\x02\x01\x20"),
        try pss(scratch, 5, 5, 32, ""),
    };
    for (invalid) |encoded| {
        const der = try certificate(encoded, 1);
        defer a.free(der);
        try testing.expectError(error.TlsTrustStoreLoadFailed, disallowed.parse(der));
    }
    const der = try certificate(null, 1);
    defer a.free(der);
    const parsed = try x509.parse(der);
    const changed = try a.dupe(u8, der);
    defer a.free(changed);
    const oid_index = @intFromPtr(parsed.algorithm.oid.ptr) - @intFromPtr(der.ptr);
    changed[oid_index + parsed.algorithm.oid.len - 1] ^= 1;
    try testing.expectError(error.TlsMalformedCertificate, disallowed.parse(changed));
    @memcpy(changed, der);
    var outer = x509.Reader.init(parsed.spki);
    var spki = x509.Reader.init((try outer.take(0x30)).content);
    const key_algorithm = try spki.take(0x30);
    var key_id = x509.Reader.init(key_algorithm.content);
    const key_oid = (try key_id.take(0x06)).content;
    const key_index = @intFromPtr(key_oid.ptr) - @intFromPtr(der.ptr);
    changed[key_index + key_oid.len - 1] = 2;
    try testing.expectError(error.TlsTrustStoreLoadFailed, disallowed.parse(changed));
    @memcpy(changed, der);
    const bits = (try spki.take(0x03)).content;
    changed[@intFromPtr(bits.ptr) - @intFromPtr(der.ptr)] = 1;
    try testing.expectError(error.TlsMalformedCertificate, disallowed.parse(changed));
}

test "Disallowed OR matching keeps same-key different-TBS and full-DER domains independent" {
    const first = try certificate(null, 1);
    defer a.free(first);
    const second = try certificate(null, 2);
    defer a.free(second);
    const one = try disallowed.parse(first);
    const two = try disallowed.parse(second);
    try testing.expectEqualSlices(u8, one.public_key_bits, two.public_key_bits);
    try testing.expect(!std.mem.eql(u8, one.tbs_der, two.tbs_der));
    var key: [16]u8 = undefined;
    var tbs: [32]u8 = undefined;
    var whole: [32]u8 = undefined;
    try reference(.md5, one.public_key_bits, &key);
    try reference(.sha256, one.tbs_der, &tbs);
    try reference(.sha256, first, &whole);
    for ([_][]const u8{ &key, &tbs, &whole }) |identifier| {
        var snapshot = platform.Snapshot.init(a, .{});
        defer snapshot.deinit();
        try add(&snapshot, &.{.{ .identifier = identifier }});
        var standard = Standard.initWithOptions(testing.io, a, .{ .allow_md5_identifier_hash = true });
        var adapter = Adapter.init(standard.provider());
        const hasher = adapter.metadataHasher(both);
        const key_match = identifier.ptr == &key;
        const tbs_match = identifier.ptr == &tbs;
        try testing.expectEqual(if (key_match or tbs_match) platform.Decision.deny else .anchor, try snapshot.check(first, use, hasher, a));
        try testing.expectEqual(if (key_match) platform.Decision.deny else .anchor, try snapshot.check(second, use, hasher, a));
    }
    // Exact lengths matter even when every byte of the shorter identifier agrees.
    var padded: [32]u8 = @splat(0);
    @memcpy(padded[0..16], &key);
    var snapshot = platform.Snapshot.init(a, .{});
    defer snapshot.deinit();
    try add(&snapshot, &.{.{ .identifier = &padded }});
    var standard = Standard.initWithOptions(testing.io, a, .{ .allow_md5_identifier_hash = true });
    var adapter = Adapter.init(standard.provider());
    try testing.expectEqual(platform.Decision.anchor, try snapshot.check(first, use, adapter.metadataHasher(both), a));
}

test "Disallowed requires both identities even for empty lists and caches repeated lists only per operation" {
    const der = try certificate(null, 1);
    defer a.free(der);
    var snapshot = platform.Snapshot.init(a, .{});
    defer snapshot.deinit();
    try add(&snapshot, &.{});
    try add(&snapshot, &.{.{ .identifier = "\x42" ** 48 }});
    var standard = Standard.initWithOptions(testing.io, a, .{ .allow_md5_identifier_hash = true });
    var spy = Spy{ .selected = standard.provider(), .inputs = try disallowed.parse(der) };
    for (1..3) |operation| {
        try testing.expectEqual(platform.Decision.anchor, try snapshot.check(der, use, spy.hasher(), a));
        try testing.expectEqual(operation, spy.key_calls);
        try testing.expectEqual(operation, spy.tbs_calls);
    }
    for ([_]p.ProviderError{ error.UnsupportedAlgorithm, error.InternalError, error.OutOfMemory }) |failure| {
        for ([_]usize{ 1, 2 }) |fail_at| {
            spy.calls = 0;
            spy.fail_at = fail_at;
            spy.failure = failure;
            try testing.expectError(if (failure == error.OutOfMemory) error.OutOfMemory else error.TlsTrustStoreLoadFailed, snapshot.check(der, use, spy.hasher(), a));
            try testing.expectEqual(fail_at, spy.calls);
        }
    }
    spy.fail_at = 0;
    try testing.expectEqual(platform.Decision.anchor, try snapshot.check(der, use, spy.hasher(), a));
    var key: [16]u8 = undefined;
    try reference(.md5, spy.inputs.public_key_bits, &key);
    var deny = platform.Snapshot.init(a, .{});
    defer deny.deinit();
    try add(&deny, &.{.{ .identifier = &key }});
    spy.calls = 0;
    spy.fail_at = 2;
    try testing.expectEqual(platform.Decision.deny, try deny.check(der, use, spy.hasher(), a));
    try testing.expectEqual(@as(usize, 1), spy.calls);
}

test "Disallowed MD5 identities never substitute complete certificate SPKI or TBS contents" {
    const der = try certificate(md5_rsa, 1);
    defer a.free(der);
    const parsed = try x509.parse(der);
    var tbs_reader = x509.Reader.init(parsed.tbs);
    const tbs_contents = (try tbs_reader.take(0x30)).content;
    var standard = Standard.initWithOptions(testing.io, a, .{ .allow_md5_identifier_hash = true });
    var adapter = Adapter.init(standard.provider());
    for ([_][]const u8{ der, parsed.spki, tbs_contents, parsed.signature_bytes }) |wrong_domain| {
        var identifier: [16]u8 = undefined;
        try reference(.md5, wrong_domain, &identifier);
        var snapshot = platform.Snapshot.init(a, .{});
        defer snapshot.deinit();
        try add(&snapshot, &.{.{ .identifier = &identifier }});
        try testing.expectEqual(platform.Decision.anchor, try snapshot.check(der, use, adapter.metadataHasher(both), a));
    }
}

test "Disallowed honors independent captured permissions backend opt-in and ABI1 refusal" {
    var snapshot = platform.Snapshot.init(a, .{});
    defer snapshot.deinit();
    try add(&snapshot, &.{});
    for ([_]?[]const u8{ null, pss_default }) |encoded| {
        const der = try certificate(encoded, 1);
        defer a.free(der);
        for ([_]bool{ false, true }) |backend| {
            var standard = Standard.initWithOptions(testing.io, a, .{ .allow_md5_identifier_hash = backend });
            var adapter = Adapter.init(standard.provider());
            for ([_]digest.Options{ .{}, .{ .allow_sha1_identifiers = true }, .{ .allow_md5_identifiers = true }, both }) |options| {
                const result = snapshot.check(der, use, adapter.metadataHasher(options), a);
                if (backend and options.allow_md5_identifiers and (encoded == null or options.allow_sha1_identifiers))
                    try testing.expectEqual(platform.Decision.anchor, try result)
                else
                    try testing.expectError(error.TlsTrustStoreLoadFailed, result);
            }
            var relaxed = adapter.metadataHasher(.{});
            relaxed.options = both;
            try testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.check(der, use, relaxed, a));
            var legacy = standard.provider();
            legacy.abi_version = 1;
            var old_adapter = Adapter.init(legacy);
            try testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.check(der, use, old_adapter.metadataHasher(both), a));
        }
    }
}

test "Disallowed list staging and both selected-provider hash allocations fail without partial allowance" {
    const der = try certificate(null, 1);
    defer a.free(der);
    const Probe = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var snapshot = platform.Snapshot.init(allocator, .{});
            defer snapshot.deinit();
            add(&snapshot, &.{.{ .identifier = "\x42" ** 16 }}) catch |err| {
                try testing.expectEqual(@as(usize, 0), snapshot.fingerprint_entries);
                try testing.expectEqual(@as(usize, 0), snapshot.fingerprint_lists.items.len);
                return err;
            };
            var standard = Standard.initWithOptions(testing.io, allocator, .{ .allow_md5_identifier_hash = true });
            var adapter = Adapter.init(standard.provider());
            try testing.expectEqual(platform.Decision.anchor, try snapshot.check(bytes, use, adapter.metadataHasher(both), allocator));
        }
    };
    try testing.checkAllAllocationFailures(a, Probe.run, .{der});
}
