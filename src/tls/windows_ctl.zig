//! Bounded interpretation of CTL_INFO DER obtained from trusted local Windows
//! stores/cache. This is not a CMS signature verifier or a downloaded-root
//! importer. CTLs add restrictions only; they never create trust anchors.
const std = @import("std");
const builtin = @import("builtin");
const x509 = @import("x509_policy.zig");
const platform = @import("platform_trust.zig");
const crypto = @import("crypto/provider.zig");
const Error = @import("trust.zig").TrustError;
const Reader = x509.Reader;

pub const authroot_usage = "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x09";
pub const disallowed_usage = "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x1e";
const property_prefix = "\x2b\x06\x01\x04\x01\x82\x37\x0a\x0b";

pub fn append(snapshot: *platform.Snapshot, expected: platform.FingerprintList.Kind, bytes: []const u8) Error!void {
    if (bytes.len == 0 or bytes.len > snapshot.limits.max_ctl_bytes or
        snapshot.fingerprint_lists.items.len >= snapshot.limits.max_fingerprint_lists)
        return error.TlsTrustStoreLoadFailed;
    const usage_oid = switch (expected) {
        .authroot => authroot_usage,
        .disallowed => disallowed_usage,
        .constraints => return error.TlsInvalidTrustConfiguration,
    };
    var list = try sequence(bytes);
    if (list.peek() == 0x02) {
        if (!std.mem.eql(u8, (try list.take(0x02)).content, "\x00"))
            return error.TlsTrustStoreLoadFailed;
    }
    var usages = Reader.init((try list.take(0x30)).content);
    if (!std.mem.eql(u8, (try usages.take(0x06)).content, usage_oid)) return error.TlsTrustStoreLoadFailed;
    try usages.finish();
    if (list.peek() == 0x04) {
        if ((try list.take(0x04)).content.len > 256) return error.TlsTrustStoreLoadFailed;
    }
    if (list.peek() == 0x02) try sequenceNumber((try list.take(0x02)).content);
    const this_update = try x509.parseTime(try list.any());
    const next_update: ?i64 = if (list.peek() == 0x17 or list.peek() == 0x18)
        try x509.parseTime(try list.any())
    else
        null;
    const algorithm = try hashAlgorithm((try list.take(0x30)).content);
    var entries: std.ArrayList(platform.FingerprintEntry) = .empty;
    defer entries.deinit(snapshot.allocator);
    if (list.peek() == 0x30) {
        var subjects = Reader.init((try list.take(0x30)).content);
        const remaining = snapshot.limits.max_fingerprint_entries - snapshot.fingerprint_entries;
        while (subjects.peek() != null) {
            if (entries.items.len >= remaining) return error.TlsTrustStoreLoadFailed;
            const entry = try readEntry((try subjects.take(0x30)).content, expected, algorithm, snapshot.limits.max_property_bytes);
            try entries.append(snapshot.allocator, entry);
        }
    }
    // No CTL-wide extension/policy is silently discarded, including one
    // whose criticality could affect how individual subjects are interpreted.
    if (list.peek() != null) return error.TlsTrustStoreLoadFailed;
    try snapshot.addFingerprintList(.{
        .kind = expected,
        .algorithm = algorithm,
        .this_update = this_update,
        .next_update = next_update,
        .entries = entries.items,
    });
}

fn sequence(bytes: []const u8) Error!Reader {
    var outer = Reader.init(bytes);
    const value = try outer.take(0x30);
    try outer.finish();
    return Reader.init(value.content);
}

fn sequenceNumber(bytes: []const u8) Error!void {
    if (bytes.len == 0 or bytes.len > 32 or bytes[0] & 0x80 != 0 or
        (bytes.len > 1 and bytes[0] == 0 and bytes[1] & 0x80 == 0))
        return error.TlsTrustStoreLoadFailed;
}

fn hashAlgorithm(bytes: []const u8) Error!crypto.HashAlgorithm {
    var algorithm = Reader.init(bytes);
    const oid = (try algorithm.take(0x06)).content;
    if (algorithm.peek() != null) {
        if ((try algorithm.take(0x05)).content.len != 0) return error.TlsTrustStoreLoadFailed;
    }
    try algorithm.finish();
    if (std.mem.eql(u8, oid, "\x2b\x0e\x03\x02\x1a")) return .sha1;
    if (std.mem.eql(u8, oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x01")) return .sha256;
    if (std.mem.eql(u8, oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x02")) return .sha384;
    if (std.mem.eql(u8, oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x03")) return .sha512;
    // In particular, MD5 identifiers do not acquire a fallback implementation.
    return error.TlsTrustStoreLoadFailed;
}

fn readEntry(bytes: []const u8, kind: platform.FingerprintList.Kind, algorithm: crypto.HashAlgorithm, property_limit: usize) Error!platform.FingerprintEntry {
    var subject = Reader.init(bytes);
    var result = try platform.FingerprintEntry.init(algorithm, (try subject.take(0x04)).content, .{
        .roles = if (kind == .disallowed) 0 else 3,
    });
    if (subject.peek() != null) {
        var attributes = Reader.init((try subject.take(0x31)).content);
        var seen: [64]u32 = undefined;
        var count: usize = 0;
        while (attributes.peek() != null) {
            if (count == seen.len) return error.TlsTrustStoreLoadFailed;
            var attribute = Reader.init((try attributes.take(0x30)).content);
            const id = try propertyId((try attribute.take(0x06)).content);
            for (seen[0..count]) |previous| {
                if (previous == id) return error.TlsTrustStoreLoadFailed;
            }
            seen[count] = id;
            count += 1;
            var values = Reader.init((try attribute.take(0x31)).content);
            const value = (try values.take(0x04)).content;
            if (value.len > property_limit) return error.TlsTrustStoreLoadFailed;
            try values.finish();
            try attribute.finish();
            switch (id) {
                9 => result.policy.roles &= try roles(value, false),
                11 => {
                    // Bounded display text, not an authority or matching key.
                    if (value.len % 2 != 0) return error.TlsTrustStoreLoadFailed;
                },
                20, 29 => {
                    // AuthRoot locator metadata does not alter its explicitly
                    // declared whole-certificate SubjectAlgorithm. Do not
                    // interpret these as alternative Disallowed selectors.
                    if (kind != .authroot or (id == 20 and (value.len == 0 or value.len > 64)) or
                        (id == 29 and value.len != 16)) return error.TlsTrustStoreLoadFailed;
                },
                98, 107 => {
                    if (value.len != 32) return error.TlsTrustStoreLoadFailed;
                    if (result.sha256) |previous| {
                        if (!std.mem.eql(u8, &previous, value)) return error.TlsTrustStoreLoadFailed;
                    }
                    result.sha256 = value[0..32].*;
                },
                104, 128 => result.policy.merge(.{ .disallow_at = try filetime(kind, id, value) }),
                122 => {
                    const denied = try roles(value, true);
                    result.policy.denied_roles |= if (denied == 0) @as(u2, 3) else denied;
                },
                83, 84, 105, 126, 127 => result.policy.unsupported = true,
                // Signature/public-key hash selectors and unknown property
                // semantics cannot be dropped based on a DER-hash nonmatch.
                else => return error.TlsTrustStoreLoadFailed,
            }
        }
    }
    try subject.finish();
    return result;
}

fn propertyId(oid: []const u8) Error!u32 {
    if (!std.mem.startsWith(u8, oid, property_prefix)) return error.TlsTrustStoreLoadFailed;
    const suffix = oid[property_prefix.len..];
    if (suffix.len == 0 or suffix.len > 2 or suffix[0] == 0x80) return error.TlsTrustStoreLoadFailed;
    var result: u32 = 0;
    for (suffix, 0..) |byte, i| {
        if ((byte & 0x80 != 0) != (i + 1 < suffix.len)) return error.TlsTrustStoreLoadFailed;
        result = result * 128 + (byte & 0x7f);
    }
    return result;
}

fn roles(bytes: []const u8, deny_unknown: bool) Error!u2 {
    var values = try sequence(bytes);
    var result: u2 = 0;
    var count: usize = 0;
    while (values.peek() != null) {
        if (count == 256) return error.TlsTrustStoreLoadFailed;
        count += 1;
        const oid = (try values.take(0x06)).content;
        if (oid.len == 0 or oid.len > 128 or oid[oid.len - 1] & 0x80 != 0)
            return error.TlsTrustStoreLoadFailed;
        var first = true;
        for (oid) |byte| {
            if (first and byte == 0x80) return error.TlsTrustStoreLoadFailed;
            first = byte & 0x80 == 0;
        }
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x05\x05\x07\x03\x01")) {
            result |= 1;
        } else if (std.mem.eql(u8, oid, "\x2b\x06\x01\x05\x05\x07\x03\x02")) {
            result |= 2;
        } else if (std.mem.eql(u8, oid, "\x55\x1d\x25\x00") or deny_unknown) {
            result = 3;
        }
    }
    return result;
}

fn filetime(kind: platform.FingerprintList.Kind, property_id: u32, bytes: []const u8) Error!i64 {
    if (bytes.len != 8) {
        if (builtin.is_test and builtin.os.tag == .windows) {
            // One structural line before this CTL load aborts; never emit
            // identifiers, certificate data, timestamps, or raw value bytes.
            std.debug.print("Windows CTL time property: kind={s} id={d} length={d} shape={s}\n", .{
                @tagName(kind),
                property_id,
                bytes.len,
                @tagName(timeValueShape(bytes)),
            });
        }
        return error.TlsTrustStoreLoadFailed;
    }
    return @as(i64, @intCast(std.mem.readInt(u64, bytes[0..8], .little) / 10_000_000)) - 11_644_473_600;
}

const TimeValueShape = enum { empty, non_der, der_octets, der_sequence, der_utc_time, der_generalized_time, der_other };

fn timeValueShape(bytes: []const u8) TimeValueShape {
    if (bytes.len == 0) return .empty;
    var reader = Reader.init(bytes);
    const value = reader.any() catch return .non_der;
    reader.finish() catch return .non_der;
    return switch (value.tag) {
        0x04 => .der_octets,
        0x30 => .der_sequence,
        0x17 => .der_utc_time,
        0x18 => .der_generalized_time,
        else => .der_other,
    };
}

test "CTL time diagnostics classify only complete structural envelopes" {
    const t = std.testing;
    try t.expectEqual(TimeValueShape.empty, timeValueShape(""));
    try t.expectEqual(TimeValueShape.non_der, timeValueShape("not DER"));
    try t.expectEqual(TimeValueShape.der_octets, timeValueShape("\x04\x08abcdefgh"));
    try t.expectEqual(TimeValueShape.der_octets, timeValueShape("\x04\x08ijklmnop"));
    try t.expectEqual(TimeValueShape.der_sequence, timeValueShape("\x30\x00"));
    try t.expectEqual(TimeValueShape.der_utc_time, timeValueShape("\x17\x0d250101000000Z"));
    try t.expectEqual(TimeValueShape.der_generalized_time, timeValueShape("\x18\x0f20250101000000Z"));
    try t.expectEqual(TimeValueShape.der_other, timeValueShape("\x05\x00"));
    for ([_][]const u8{ "\x04\x08short", "\x04\x08abcdefgh\x00", "\x04\x81\x08abcdefgh", "\x04\x80\x00\x00" }) |bytes| {
        try t.expectEqual(TimeValueShape.non_der, timeValueShape(bytes));
    }
}
