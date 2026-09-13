//! Read-only Crypt32 store/metadata discovery; never invokes a chain engine.
const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const crypt32 = windows.crypt32;
const metadata = @import("platform_trust.zig");
const x509 = @import("x509_policy.zig");
const Error = @import("trust.zig").TrustError;
const Allocator = std.mem.Allocator;
const not_found: u32 = 0x80092004; // CRYPT_E_NOT_FOUND

extern "crypt32" fn CertGetEnhancedKeyUsage(*const crypt32.CERT_CONTEXT, u32, ?*anyopaque, *u32) callconv(.winapi) windows.BOOL;
extern "crypt32" fn CertGetCertificateContextProperty(*const crypt32.CERT_CONTEXT, u32, ?*anyopaque, *u32) callconv(.winapi) windows.BOOL;
extern "crypt32" fn CertEnumCTLsInStore(crypt32.HCERTSTORE, ?*const anyopaque) callconv(.winapi) ?*const anyopaque;
extern "crypt32" fn CertFreeCTLContext(?*const anyopaque) callconv(.winapi) windows.BOOL;
extern "crypt32" fn CertCreateCertificateContext(crypt32.ENCODING.TYPE, [*]const u8, u32) callconv(.winapi) ?*const crypt32.CERT_CONTEXT;

pub fn load(allocator: Allocator, limits: metadata.Limits) Error!metadata.Snapshot {
    if (comptime builtin.os.tag != .windows) return error.TlsTrustStoreLoadFailed;
    if (try hasUnsupportedCachedCtl()) return error.TlsTrustStoreLoadFailed;
    var snapshot = metadata.Snapshot.init(allocator, limits);
    errdefer snapshot.deinit();
    // CURRENT_USER's logical ROOT includes machine roots; explicitly read
    // machine scope too so restrictive duplicate properties intersect.
    for ([_]u16{ 1, 2 }) |scope| {
        try readStore(&snapshot, scope, std.unicode.utf8ToUtf16LeStringLiteral("ROOT"), true);
        try readStore(&snapshot, scope, std.unicode.utf8ToUtf16LeStringLiteral("Disallowed"), false);
    }
    return snapshot;
}

/// Cached AuthRoot/Disallowed CTLs live outside the logical certificate stores.
/// Until their hash-only entries can be matched through an approved primitive
/// seam, detecting them must block discovery rather than silently omit them.
pub fn hasUnsupportedCachedCtl() Error!bool {
    if (comptime builtin.os.tag != .windows) return false;
    const path = std.unicode.utf8ToUtf16LeStringLiteral("\\Registry\\Machine\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\AutoUpdate");
    var name = windows.UNICODE_STRING.init(path);
    const attributes: windows.OBJECT.ATTRIBUTES = .{ .ObjectName = &name };
    var key: windows.HANDLE = undefined;
    // KEY_QUERY_VALUE | KEY_WOW64_64KEY, never write/create access.
    switch (windows.ntdll.NtOpenKey(&key, .{ .SPECIFIC = .{ .bits = 0x0101 } }, &attributes)) {
        .SUCCESS => {},
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return false,
        else => return error.TlsTrustStoreLoadFailed,
    }
    defer _ = windows.ntdll.NtClose(key);
    inline for (.{ "EncodedCtl", "DisallowedCertEncodedCtl" }) |value| {
        var value_name = windows.UNICODE_STRING.init(std.unicode.utf8ToUtf16LeStringLiteral(value));
        var buffer: [16]u8 align(@alignOf(windows.KEY.VALUE.PARTIAL_INFORMATION)) = undefined;
        var length: u32 = 0;
        switch (windows.ntdll.NtQueryValueKey(key, &value_name, .Partial, &buffer, buffer.len, &length)) {
            .SUCCESS, .BUFFER_OVERFLOW, .BUFFER_TOO_SMALL => return true,
            .OBJECT_NAME_NOT_FOUND => {},
            else => return error.TlsTrustStoreLoadFailed,
        }
    }
    return false;
}

fn readStore(snapshot: *metadata.Snapshot, scope: u16, name: [*:0]const u16, roots: bool) Error!void {
    const store = crypt32.CertOpenStore(.SYSTEM_W, .{}, .NULL, .{
        .OPEN_EXISTING = true,
        .READONLY = true,
        .Reserved16 = scope,
    }, name) orelse {
        // An absent disallowed store is distinct from an unreadable store.
        const code = @intFromEnum(windows.GetLastError());
        if (!roots and (code == 2 or code == not_found)) return;
        return error.TlsTrustStoreLoadFailed;
    };
    defer _ = crypt32.CertCloseStore(store, .{});
    if (CertEnumCTLsInStore(store, null)) |ctl| {
        _ = CertFreeCTLContext(ctl);
        // Hash-only CTL matching is not exposed by the signature-only ABI.
        return error.TlsTrustStoreLoadFailed;
    }
    if (@intFromEnum(windows.GetLastError()) != not_found) return error.TlsTrustStoreLoadFailed;
    var current: ?*crypt32.CERT_CONTEXT = null;
    defer if (current) |certificate| {
        _ = crypt32.CertFreeCertificateContext(certificate);
    };
    var count: usize = 0;
    while (true) {
        // Enumeration consumes the previous context, including on failure.
        current = crypt32.CertEnumCertificatesInStore(store, current);
        const certificate = current orelse {
            if (@intFromEnum(windows.GetLastError()) != not_found) return error.TlsTrustStoreLoadFailed;
            break;
        };
        count += 1;
        if (count > snapshot.limits.max_certificates) return error.TlsTrustStoreLoadFailed;
        const index = try snapshot.add(certificate.pbCertEncoded[0..certificate.cbCertEncoded], roots);
        const policy = if (roots) try readPolicy(snapshot, certificate) else metadata.Windows{ .roles = 0 };
        const entry = &snapshot.entries.items[index];
        if (entry.windows) |*prior| prior.merge(policy) else entry.windows = policy;
    }
}

fn readPolicy(snapshot: *metadata.Snapshot, certificate: *const crypt32.CERT_CONTEXT) Error!metadata.Windows {
    const roles = try effectiveRoles(snapshot.allocator, snapshot.limits.max_property_bytes, certificate);
    return readPolicyProperties(snapshot.allocator, snapshot.limits.max_property_bytes, .{
        .context = certificate,
        .function = queryProperty,
    }, roles);
}

const cert_not_before_filetime_prop_id: u32 = 126;
const cert_not_before_enhkey_usage_prop_id: u32 = 127;

fn readPolicyProperties(allocator: Allocator, limit: usize, query: Query, roles: u2) Error!metadata.Windows {
    var result = metadata.Windows{ .roles = roles };
    // These properties encode additional policies that this offline profile
    // does not implement. Presence is restrictive, never unrestricted trust.
    for ([_]u32{ 83, 84, 105, cert_not_before_filetime_prop_id, cert_not_before_enhkey_usage_prop_id }) |property_id| {
        if (try readProperty(allocator, limit, query, property_id)) |bytes| {
            defer allocator.free(bytes);
            result.unsupported = true;
        }
    }
    for ([_]u32{ 104, 128 }) |property_id| {
        if (try readProperty(allocator, limit, query, property_id)) |bytes| {
            defer allocator.free(bytes);
            result.merge(.{ .disallow_at = try filetime(bytes) });
        }
    }
    if (try readProperty(allocator, limit, query, 122)) |bytes| {
        defer allocator.free(bytes);
        result.denied_roles = try deniedRoles(bytes);
    }
    return result;
}

const QueryError = error{ Missing, Failure };
const Query = struct {
    context: *const anyopaque,
    function: *const fn (*const anyopaque, u32, ?[]u8) QueryError!usize,
};

fn property(allocator: Allocator, limit: usize, certificate: *const crypt32.CERT_CONTEXT, id: u32) Error!?[]u8 {
    return readProperty(allocator, limit, .{ .context = certificate, .function = queryProperty }, id);
}

fn queryProperty(context: *const anyopaque, id: u32, buffer: ?[]u8) QueryError!usize {
    const certificate: *const crypt32.CERT_CONTEXT = @ptrCast(@alignCast(context));
    var size: u32 = if (buffer) |bytes| @intCast(bytes.len) else 0;
    if (!CertGetCertificateContextProperty(certificate, id, if (buffer) |bytes| bytes.ptr else null, &size).toBool()) {
        return if (@intFromEnum(windows.GetLastError()) == not_found) error.Missing else error.Failure;
    }
    return size;
}

fn readProperty(allocator: Allocator, limit: usize, query: Query, id: u32) Error!?[]u8 {
    const needed = query.function(query.context, id, null) catch |err| return switch (err) {
        error.Missing => null,
        error.Failure => error.TlsTrustStoreLoadFailed,
    };
    if (needed == 0 or needed > limit or needed > std.math.maxInt(u32)) return error.TlsTrustStoreLoadFailed;
    const bytes = try allocator.alloc(u8, needed);
    errdefer allocator.free(bytes);
    const actual = query.function(query.context, id, bytes) catch return error.TlsTrustStoreLoadFailed;
    if (actual != needed) return error.TlsTrustStoreLoadFailed;
    return bytes;
}

fn effectiveRoles(allocator: Allocator, limit: usize, certificate: *const crypt32.CERT_CONTEXT) Error!u2 {
    var size: u32 = 0;
    if (!CertGetEnhancedKeyUsage(certificate, 0, null, &size).toBool() or
        size < @sizeOf(crypt32.CERT_ENHKEY_USAGE) or size > limit) return error.TlsTrustStoreLoadFailed;
    const buffer = try allocator.alignedAlloc(u8, .of(crypt32.CERT_ENHKEY_USAGE), size);
    defer allocator.free(buffer);
    windows.teb().LastErrorValue = .SUCCESS;
    if (!CertGetEnhancedKeyUsage(certificate, 0, buffer.ptr, &size).toBool() or size != buffer.len)
        return error.TlsTrustStoreLoadFailed;
    const last_error = @intFromEnum(windows.GetLastError());
    const usage: *const crypt32.CERT_ENHKEY_USAGE = @ptrCast(buffer.ptr);
    if (usage.cUsageIdentifier == 0) return emptyRoles(last_error);
    if (usage.cUsageIdentifier > 256) return error.TlsTrustStoreLoadFailed;
    const pointers = try within(buffer, @intFromPtr(usage.rgpszUsageIdentifier), @as(usize, usage.cUsageIdentifier) * @sizeOf(usize));
    var roles: u2 = 0;
    for (0..usage.cUsageIdentifier) |i| {
        const address = std.mem.readInt(usize, pointers[i * @sizeOf(usize) ..][0..@sizeOf(usize)], .little);
        const start = try within(buffer, address, 1);
        const remaining = buffer[@intFromPtr(start.ptr) - @intFromPtr(buffer.ptr) ..];
        const end = std.mem.indexOfScalar(u8, remaining, 0) orelse return error.TlsTrustStoreLoadFailed;
        if (end == 0 or end > 128) return error.TlsTrustStoreLoadFailed;
        const oid = remaining[0..end];
        if (std.mem.eql(u8, oid, "1.3.6.1.5.5.7.3.1")) roles |= 1;
        if (std.mem.eql(u8, oid, "1.3.6.1.5.5.7.3.2")) roles |= 2;
        if (std.mem.eql(u8, oid, "2.5.29.37.0")) roles = 3;
    }
    return roles;
}

fn emptyRoles(last_error: u32) Error!u2 {
    return switch (last_error) {
        0 => 0,
        not_found => 3,
        else => error.TlsTrustStoreLoadFailed,
    };
}

fn within(buffer: []const u8, address: usize, length: usize) Error![]const u8 {
    const begin = @intFromPtr(buffer.ptr);
    if (address < begin or address - begin > buffer.len or length > buffer.len - (address - begin))
        return error.TlsTrustStoreLoadFailed;
    return buffer[address - begin ..][0..length];
}

fn filetime(bytes: []const u8) Error!i64 {
    if (bytes.len != 8) return error.TlsTrustStoreLoadFailed;
    const ticks = std.mem.readInt(u64, bytes[0..8], .little);
    return @as(i64, @intCast(ticks / 10_000_000)) - 11_644_473_600;
}

fn deniedRoles(bytes: []const u8) Error!u2 {
    var outer = x509.Reader.init(bytes);
    var sequence = x509.Reader.init((try outer.take(0x30)).content);
    try outer.finish();
    var roles: u2 = 0;
    var count: usize = 0;
    while (sequence.peek() != null) {
        count += 1;
        if (count > 256) return error.TlsTrustStoreLoadFailed;
        const oid = (try sequence.take(0x06)).content;
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x05\x05\x07\x03\x01")) {
            roles |= 1;
        } else if (std.mem.eql(u8, oid, "\x2b\x06\x01\x05\x05\x07\x03\x02")) {
            roles |= 2;
        } else {
            // Unknown/any/empty disabled-purpose data is not interpreted as
            // permission for TLS.
            roles = 3;
        }
    }
    return if (count == 0) 3 else roles;
}

test "Windows missing versus disabled usage and bounded pointers" {
    try std.testing.expectEqual(@as(u2, 3), try emptyRoles(not_found));
    try std.testing.expectEqual(@as(u2, 0), try emptyRoles(0));
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, emptyRoles(5));
    const buffer = [_]u8{ 1, 2, 3 };
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, within(&buffer, @intFromPtr(&buffer) + 2, 2));
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, within(&buffer, std.math.maxInt(usize), 1));
    try std.testing.expectEqualSlices(u8, &.{2}, try within(&buffer, @intFromPtr(&buffer) + 1, 1));
}

test "Windows property query failure size races and allocation ownership" {
    const Fake = struct {
        size: usize = 4,
        fail_read: bool = false,
        changed_size: bool = false,
        fn query(context: *const anyopaque, _: u32, buffer: ?[]u8) QueryError!usize {
            const self: *const @This() = @ptrCast(@alignCast(context));
            if (buffer) |bytes| {
                if (self.fail_read) return error.Failure;
                @memset(bytes, 0);
                return if (self.changed_size) bytes.len - 1 else bytes.len;
            }
            return self.size;
        }
        fn allocated(allocator: Allocator) !void {
            const self = @This(){};
            const bytes = (try readProperty(allocator, 8, .{ .context = &self, .function = query }, 9)).?;
            defer allocator.free(bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Fake.allocated, .{});
    for ([_]Fake{ .{ .size = 0 }, .{ .size = 9 }, .{ .fail_read = true }, .{ .changed_size = true } }) |fake| {
        try std.testing.expectError(error.TlsTrustStoreLoadFailed, readProperty(std.testing.allocator, 8, .{ .context = &fake, .function = Fake.query }, 9));
    }
}

const IssuancePropertyQuery = struct {
    present: u2,
    queried: u2 = 0,
    read: u2 = 0,
    failure: enum { none, size_query, read_query, size_changed } = .none,

    fn query(context: *const anyopaque, id: u32, buffer: ?[]u8) QueryError!usize {
        const self: *@This() = @ptrCast(@alignCast(@constCast(context)));
        const bit: u2 = switch (id) {
            cert_not_before_filetime_prop_id => 1,
            cert_not_before_enhkey_usage_prop_id => 2,
            else => return error.Missing,
        };
        self.queried |= bit;
        if (self.present & bit == 0) return error.Missing;
        const value: []const u8 = if (bit == 1)
            "\x00\x00\x00\x00\x00\x00\x00\x00"
        else
            "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01";
        if (buffer) |bytes| {
            if (self.failure == .read_query) return error.Failure;
            @memcpy(bytes, value);
            self.read |= bit;
            return if (self.failure == .size_changed) bytes.len - 1 else bytes.len;
        }
        if (self.failure == .size_query) return error.Failure;
        return value.len;
    }

    fn descriptor(self: *@This()) Query {
        return .{ .context = self, .function = query };
    }
};

test "Windows policy dispatch detects both issuance restriction properties without a CTL" {
    for ([_]u2{ 0, 1, 2, 3 }) |present| {
        var fixture = IssuancePropertyQuery{ .present = present };
        const result = try readPolicyProperties(std.testing.allocator, 16, fixture.descriptor(), 3);
        try std.testing.expectEqual(@as(u2, 3), fixture.queried);
        try std.testing.expectEqual(present, fixture.read);
        try std.testing.expectEqual(present != 0, result.unsupported);
        for ([_]@import("trust.zig").PeerRole{ .server, .client }) |role| {
            try std.testing.expectEqual(present == 0, result.permits(.{
                .role = role,
                .identity = null,
                .now_seconds = 1_800_000_000,
                .issuer = true,
                .self_issued = true,
            }));
        }
    }
}

test "Windows issuance property dispatch preserves errors bounds and allocation cleanup" {
    const Test = struct {
        fn run(allocator: Allocator) !void {
            var fixture = IssuancePropertyQuery{ .present = 3 };
            const result = try readPolicyProperties(allocator, 16, fixture.descriptor(), 3);
            try std.testing.expect(result.unsupported);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
    for ([_]u2{ 1, 2 }) |present| {
        var fixture = IssuancePropertyQuery{ .present = present };
        inline for (.{ .size_query, .read_query, .size_changed }) |failure| {
            fixture.failure = failure;
            try std.testing.expectError(error.TlsTrustStoreLoadFailed, readPolicyProperties(std.testing.allocator, 16, fixture.descriptor(), 3));
        }
        fixture.failure = .none;
        try std.testing.expectError(error.TlsTrustStoreLoadFailed, readPolicyProperties(std.testing.allocator, 1, fixture.descriptor(), 3));
    }
}

test "Windows time and disabled purpose metadata are strict" {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, 116_444_736_000_000_000, .little);
    try std.testing.expectEqual(@as(i64, 0), try filetime(&bytes));
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, filetime(bytes[0..7]));
    try std.testing.expectEqual(@as(u2, 1), try deniedRoles("\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01"));
    try std.testing.expectEqual(@as(u2, 3), try deniedRoles("\x30\x00"));
    try std.testing.expectError(error.TlsMalformedCertificate, deniedRoles("\x30\x03\x06\x02\x00"));
}

test "native Windows reads effective EKU from an in-memory certificate without changing system stores" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const fixtures = @import("trust_fixtures.zig");
    var chain = try fixtures.Chain.init(std.testing.allocator, .ecdsa_p256);
    defer chain.deinit();
    const certificate = CertCreateCertificateContext(.{ .CERT = .ASN }, chain.leaf.ptr, @intCast(chain.leaf.len)) orelse
        return error.TlsTrustStoreLoadFailed;
    defer _ = crypt32.CertFreeCertificateContext(certificate);
    try std.testing.expectEqual(@as(u2, 1), try effectiveRoles(std.testing.allocator, 4096, certificate));
    try std.testing.expectEqual(@as(?[]u8, null), try property(std.testing.allocator, 4096, certificate, 104));
    const root = CertCreateCertificateContext(.{ .CERT = .ASN }, chain.root.ptr, @intCast(chain.root.len)) orelse
        return error.TlsTrustStoreLoadFailed;
    defer _ = crypt32.CertFreeCertificateContext(root);
    try std.testing.expectEqual(@as(u2, 3), try effectiveRoles(std.testing.allocator, 4096, root));
}
