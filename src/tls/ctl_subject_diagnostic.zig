//! Test-only structural evidence, not an identifier-domain implementation.
//! Fixed labels come from Microsoft's public wincrypt.h at commit
//! 1bfb76db1c360653bdcb56512af0fdf987aceab8: digest OIDs, property IDs/OIDs,
//! szOID_DISALLOWED_HASH (property 15), and szOID_PIN_RULES_DOMAIN_NAME.
//! CTL_ENTRY.SubjectIdentifier may be any unique byte sequence. A property
//! selector or an identifier length does not establish a whole-certificate
//! digest: property 15 uses CryptHashToBeSigned, and property 25 is a public-key
//! MD5 property. This diagnostic computes neither and retains no input bytes.
//! https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-ctl_entry
//! https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatecontextproperty
const std = @import("std");
const Reader = @import("x509_policy.zig").Reader;
const Kind = @import("platform_trust.zig").FingerprintList.Kind;
const property_prefix = "\x2b\x06\x01\x04\x01\x82\x37\x0a\x0b";
const max_bytes = 16 * 1024 * 1024;
const max_entries = 16 * 1024;

const Algorithm = enum {
    not_inspected,
    unknown,
    md2,
    md4,
    md5,
    oiw_sha,
    sha1,
    sha256,
    sha384,
    sha512,
    shake128,
    shake256,
    cert_sha1,
    cert_md5,
    signature_hash_or_disallowed_hash,
    key_identifier,
    issuer_public_key_md5,
    subject_public_key_md5,
    issuer_serial_md5,
    subject_name_md5,
    authroot_sha256,
    cert_sha256,
    cert_sha1_sha256,
    pin_rules_domain_name,
};

const names = [_]struct { oid: []const u8, name: Algorithm }{
    .{ .oid = "\x2a\x86\x48\x86\xf7\x0d\x02\x02", .name = .md2 },
    .{ .oid = "\x2a\x86\x48\x86\xf7\x0d\x02\x04", .name = .md4 },
    .{ .oid = "\x2a\x86\x48\x86\xf7\x0d\x02\x05", .name = .md5 },
    .{ .oid = "\x2b\x0e\x03\x02\x12", .name = .oiw_sha },
    .{ .oid = "\x2b\x0e\x03\x02\x1a", .name = .sha1 },
    .{ .oid = "\x60\x86\x48\x01\x65\x03\x04\x02\x01", .name = .sha256 },
    .{ .oid = "\x60\x86\x48\x01\x65\x03\x04\x02\x02", .name = .sha384 },
    .{ .oid = "\x60\x86\x48\x01\x65\x03\x04\x02\x03", .name = .sha512 },
    .{ .oid = "\x60\x86\x48\x01\x65\x03\x04\x02\x0b", .name = .shake128 },
    .{ .oid = "\x60\x86\x48\x01\x65\x03\x04\x02\x0c", .name = .shake256 },
    .{ .oid = property_prefix ++ "\x03", .name = .cert_sha1 },
    .{ .oid = property_prefix ++ "\x04", .name = .cert_md5 },
    .{ .oid = property_prefix ++ "\x0f", .name = .signature_hash_or_disallowed_hash },
    .{ .oid = property_prefix ++ "\x14", .name = .key_identifier },
    .{ .oid = property_prefix ++ "\x18", .name = .issuer_public_key_md5 },
    .{ .oid = property_prefix ++ "\x19", .name = .subject_public_key_md5 },
    .{ .oid = property_prefix ++ "\x1c", .name = .issuer_serial_md5 },
    .{ .oid = property_prefix ++ "\x1d", .name = .subject_name_md5 },
    .{ .oid = property_prefix ++ "\x62", .name = .authroot_sha256 },
    .{ .oid = property_prefix ++ "\x6b", .name = .cert_sha256 },
    .{ .oid = property_prefix ++ "\x81\x01", .name = .cert_sha1_sha256 },
    .{ .oid = "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x22", .name = .pin_rules_domain_name },
};

pub const Summary = struct {
    kind: Kind,
    algorithm: Algorithm = .not_inspected,
    parameters: enum { not_inspected, absent, null_value, sequence, octets, other, malformed } = .not_inspected,
    parameter_length: usize = 0,
    identifier_scan: enum { absent, complete, malformed, limited } = .absent,
    entries: usize = 0,
    // Fixed buckets only: no individual lengths, identifiers, or attributes.
    lengths: [9]usize = @splat(0),
};

pub fn inspect(kind: Kind, algorithm_bytes: []const u8, remaining: []const u8) Summary {
    var result = Summary{ .kind = kind };
    if (algorithm_bytes.len > 1024 or remaining.len > max_bytes) {
        result.identifier_scan = .limited;
        return result;
    }
    inspectAlgorithm(&result, algorithm_bytes) catch {
        result.parameters = .malformed;
        result.identifier_scan = .malformed;
        return result;
    };
    inspectIdentifiers(&result, remaining) catch {
        result.identifier_scan = .malformed;
    };
    return result;
}

fn inspectAlgorithm(result: *Summary, bytes: []const u8) !void {
    var algorithm = Reader.init(bytes);
    const oid = (try algorithm.take(0x06)).content;
    result.algorithm = .unknown;
    result.parameters = .absent;
    for (names) |entry| {
        if (std.mem.eql(u8, entry.oid, oid)) {
            result.algorithm = entry.name;
            break;
        }
    }
    if (algorithm.peek() != null) {
        const parameters = try algorithm.any();
        result.parameter_length = parameters.content.len;
        result.parameters = switch (parameters.tag) {
            0x05 => if (parameters.content.len == 0) .null_value else .malformed,
            0x30 => .sequence,
            0x04 => .octets,
            else => .other,
        };
    }
    try algorithm.finish();
}

fn inspectIdentifiers(result: *Summary, bytes: []const u8) !void {
    var remaining = Reader.init(bytes);
    if (remaining.peek() == null or remaining.peek() == 0xa0) return;
    var subjects = Reader.init((try remaining.take(0x30)).content);
    while (subjects.peek() != null) {
        if (result.entries == max_entries) {
            result.identifier_scan = .limited;
            return;
        }
        var subject = Reader.init((try subjects.take(0x30)).content);
        const identifier = try subject.take(0x04);
        if (subject.peek() != null) _ = try subject.take(0x31);
        try subject.finish();
        const bucket: usize = switch (identifier.content.len) {
            0 => 0,
            16 => 1,
            20 => 2,
            28 => 3,
            32 => 4,
            48 => 5,
            52 => 6,
            64 => 7,
            else => 8,
        };
        result.lengths[bucket] += 1;
        result.entries += 1;
    }
    // This only scans identifiers and attribute envelopes, not attribute
    // contents or later CTL extensions; it never validates their policies.
    result.identifier_scan = .complete;
}

pub fn emit(summary: Summary) void {
    if (!@import("builtin").is_test or @import("builtin").os.tag != .windows) return;
    std.debug.print("Windows CTL SubjectAlgorithm: kind={s} algorithm={s} parameters={s} parameter_length={d} identifier_scan={s} entries={d} length_counts(0,16,20,28,32,48,52,64,other)={any}\n", .{
        @tagName(summary.kind),   @tagName(summary.algorithm),       @tagName(summary.parameters),
        summary.parameter_length, @tagName(summary.identifier_scan), summary.entries,
        summary.lengths,
    });
}

test "SubjectAlgorithm diagnostic recognizes only fixed public identities without aliasing" {
    const fixture = @import("ctl_fixtures.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (names) |entry| {
        const bytes = try fixture.element(a, 0x06, entry.oid);
        try std.testing.expectEqual(entry.name, inspect(.authroot, bytes, "").algorithm);
    }
    const unknown = try fixture.element(a, 0x06, "\x2a\x03\x04");
    try std.testing.expectEqual(Algorithm.unknown, inspect(.disallowed, unknown, "").algorithm);
    try std.testing.expect(Algorithm.cert_sha1 != .sha1);
    try std.testing.expect(Algorithm.signature_hash_or_disallowed_hash != .sha1);
}

test "SubjectAlgorithm diagnostic copies bounded length counts not identifiers or parameter bytes" {
    const fixture = @import("ctl_fixtures.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var entries: std.ArrayList([]const u8) = .empty;
    for ([_]usize{ 0, 16, 20, 28, 32, 48, 52, 64, 7 }) |length| {
        const value = try a.alloc(u8, length);
        @memset(value, 0xa5);
        try entries.append(a, try fixture.element(a, 0x30, try fixture.element(a, 0x04, value)));
    }
    const subjects = try a.dupe(u8, try fixture.element(a, 0x30, try fixture.join(a, entries.items)));
    const algorithm = try a.dupe(u8, try fixture.join(a, &.{
        try fixture.element(a, 0x06, property_prefix ++ "\x0f"),
        "\x05\x00",
    }));
    const summary = inspect(.disallowed, algorithm, subjects);
    @memset(subjects, 0);
    @memset(algorithm, 0);
    try std.testing.expectEqual(Kind.disallowed, summary.kind);
    try std.testing.expectEqual(Algorithm.signature_hash_or_disallowed_hash, summary.algorithm);
    try std.testing.expectEqual(.null_value, summary.parameters);
    try std.testing.expectEqual(.complete, summary.identifier_scan);
    try std.testing.expectEqual(@as(usize, 9), summary.entries);
    try std.testing.expectEqualSlices(usize, &@as([9]usize, @splat(1)), &summary.lengths);
}

test "SubjectAlgorithm diagnostic handles malformed parameter framing and identifier scan limits" {
    const fixture = @import("ctl_fixtures.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const oid = "\x06\x05\x2b\x0e\x03\x02\x1a";
    try std.testing.expectEqual(.absent, inspect(.authroot, oid, "").parameters);
    try std.testing.expectEqual(.sequence, inspect(.authroot, oid ++ "\x30\x00", "").parameters);
    try std.testing.expectEqual(.octets, inspect(.authroot, oid ++ "\x04\x01\x7f", "").parameters);
    try std.testing.expectEqual(.other, inspect(.authroot, oid ++ "\x02\x01\x00", "").parameters);
    try std.testing.expectEqual(.malformed, inspect(.authroot, oid ++ "\x05\x01\x00", "").parameters);
    try std.testing.expectEqual(.malformed, inspect(.authroot, oid ++ "\x05\x00\x05\x00", "").parameters);
    for (0..oid.len) |length| {
        try std.testing.expectEqual(.malformed, inspect(.authroot, oid[0..length], "").parameters);
    }
    const valid = "\x30\x04\x30\x02\x04\x00";
    for (1..valid.len) |length| {
        try std.testing.expectEqual(.malformed, inspect(.authroot, oid, valid[0..length]).identifier_scan);
    }
    const entries = try a.alloc([]const u8, max_entries + 1);
    @memset(entries, "\x30\x02\x04\x00");
    const too_many = try fixture.element(a, 0x30, try fixture.join(a, entries));
    const limited = inspect(.authroot, oid, too_many);
    try std.testing.expectEqual(.limited, limited.identifier_scan);
    try std.testing.expectEqual(@as(usize, max_entries), limited.entries);
    try std.testing.expectEqual(@as(usize, max_entries), limited.lengths[0]);
    const at_limit = try fixture.element(a, 0x30, try fixture.join(a, entries[0..max_entries]));
    const complete = inspect(.authroot, oid, at_limit);
    try std.testing.expectEqual(.complete, complete.identifier_scan);
    try std.testing.expectEqual(@as(usize, max_entries), complete.entries);
    const uninspected = inspect(.authroot, &@as([1025]u8, @splat(0)), "");
    try std.testing.expectEqual(.limited, uninspected.identifier_scan);
    try std.testing.expectEqual(.not_inspected, uninspected.algorithm);
    try std.testing.expectEqual(.not_inspected, uninspected.parameters);
    const oversized = try a.alloc(u8, max_bytes + 1);
    try std.testing.expectEqual(.limited, inspect(.authroot, oid, oversized).identifier_scan);
}
