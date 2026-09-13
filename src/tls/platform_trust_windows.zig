//! Read-only Crypt32 store/metadata discovery; never invokes a chain engine.
const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const crypt32 = windows.crypt32;
const metadata = @import("platform_trust.zig");
const x509 = @import("x509_policy.zig");
const ctl_policy = @import("windows_ctl.zig");
const Error = @import("trust.zig").TrustError;
const Allocator = std.mem.Allocator;
const not_found: u32 = 0x80092004; // CRYPT_E_NOT_FOUND

extern "crypt32" fn CertGetEnhancedKeyUsage(*const crypt32.CERT_CONTEXT, u32, ?*anyopaque, *u32) callconv(.winapi) windows.BOOL;
extern "crypt32" fn CertGetCertificateContextProperty(*const crypt32.CERT_CONTEXT, u32, ?*anyopaque, *u32) callconv(.winapi) windows.BOOL;
const CtlContext = extern struct {
    encoding: crypt32.ENCODING.TYPE,
    encoded: [*]const u8,
    encoded_length: u32,
    info: *const anyopaque,
    store: ?crypt32.HCERTSTORE,
    message: ?*anyopaque,
    content: [*]const u8,
    content_length: u32,
};
extern "crypt32" fn CertEnumCTLsInStore(crypt32.HCERTSTORE, ?*const CtlContext) callconv(.winapi) ?*const CtlContext;
extern "crypt32" fn CertFreeCTLContext(?*const CtlContext) callconv(.winapi) windows.BOOL;
extern "crypt32" fn CertCreateCTLContext(crypt32.ENCODING.TYPE, [*]const u8, u32) callconv(.winapi) ?*const CtlContext;
extern "crypt32" fn CertCreateCertificateContext(crypt32.ENCODING.TYPE, [*]const u8, u32) callconv(.winapi) ?*const crypt32.CERT_CONTEXT;

pub fn load(allocator: Allocator, limits: metadata.Limits) Error!metadata.Snapshot {
    if (comptime builtin.os.tag != .windows) return error.TlsTrustStoreLoadFailed;
    var snapshot = metadata.Snapshot.init(allocator, limits);
    errdefer snapshot.deinit();
    try readCachedCtls(&snapshot);
    // CURRENT_USER's logical ROOT includes machine roots; explicitly read
    // machine scope too so restrictive duplicate properties intersect.
    for ([_]u16{ 1, 2 }) |scope| {
        try readStore(&snapshot, scope, std.unicode.utf8ToUtf16LeStringLiteral("ROOT"), .roots);
        try readStore(&snapshot, scope, std.unicode.utf8ToUtf16LeStringLiteral("Disallowed"), .disallowed);
    }
    // Cache membership marks program roots, but never imports additional
    // anchors. Their current AuthRoot CTL membership is checked at verification.
    try readStore(&snapshot, 2, std.unicode.utf8ToUtf16LeStringLiteral("AuthRoot"), .authroot_cache);
    return snapshot;
}

fn readCachedCtls(snapshot: *metadata.Snapshot) Error!void {
    const path = std.unicode.utf8ToUtf16LeStringLiteral("\\Registry\\Machine\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\AutoUpdate");
    var name = windows.UNICODE_STRING.init(path);
    const attributes: windows.OBJECT.ATTRIBUTES = .{ .ObjectName = &name };
    var key: windows.HANDLE = undefined;
    // KEY_QUERY_VALUE | KEY_WOW64_64KEY, never write/create access.
    switch (windows.ntdll.NtOpenKey(&key, .{ .SPECIFIC = .{ .bits = 0x0101 } }, &attributes)) {
        .SUCCESS => {},
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return,
        else => return error.TlsTrustStoreLoadFailed,
    }
    defer _ = windows.ntdll.NtClose(key);
    const values = [_]struct { name: [:0]const u16, kind: metadata.FingerprintList.Kind }{
        .{ .name = std.unicode.utf8ToUtf16LeStringLiteral("EncodedCtl"), .kind = .authroot },
        .{ .name = std.unicode.utf8ToUtf16LeStringLiteral("DisallowedCertEncodedCtl"), .kind = .disallowed },
    };
    for (values) |value| {
        var value_name = windows.UNICODE_STRING.init(value.name);
        const Header = windows.KEY.VALUE.PARTIAL_INFORMATION;
        var header: [@sizeOf(Header)]u8 align(@alignOf(Header)) = undefined;
        var length: u32 = 0;
        switch (windows.ntdll.NtQueryValueKey(key, &value_name, .Partial, &header, header.len, &length)) {
            .SUCCESS, .BUFFER_OVERFLOW, .BUFFER_TOO_SMALL => {},
            .OBJECT_NAME_NOT_FOUND => continue,
            else => return error.TlsTrustStoreLoadFailed,
        }
        if (length <= @sizeOf(Header) or length - @sizeOf(Header) > snapshot.limits.max_ctl_bytes)
            return error.TlsTrustStoreLoadFailed;
        const buffer = try snapshot.allocator.alignedAlloc(u8, .of(Header), length);
        defer snapshot.allocator.free(buffer);
        var actual: u32 = 0;
        if (windows.ntdll.NtQueryValueKey(key, &value_name, .Partial, buffer.ptr, length, &actual) != .SUCCESS or actual != length)
            return error.TlsTrustStoreLoadFailed;
        try appendEncodedCtl(snapshot, value.kind, try registryPayload(buffer));
    }
}

fn registryPayload(buffer: []align(@alignOf(windows.KEY.VALUE.PARTIAL_INFORMATION)) const u8) Error![]const u8 {
    const Header = windows.KEY.VALUE.PARTIAL_INFORMATION;
    if (buffer.len <= @sizeOf(Header)) return error.TlsTrustStoreLoadFailed;
    const info: *const Header = @ptrCast(buffer.ptr);
    if (info.Type != .BINARY or info.DataLength != buffer.len - @offsetOf(Header, "Data"))
        return error.TlsTrustStoreLoadFailed;
    return info.data();
}

fn appendEncodedCtl(snapshot: *metadata.Snapshot, kind: metadata.FingerprintList.Kind, encoded: []const u8) Error!void {
    if (encoded.len == 0 or encoded.len > snapshot.limits.max_ctl_bytes or
        snapshot.fingerprint_lists.items.len >= snapshot.limits.max_fingerprint_lists)
        return error.TlsTrustStoreLoadFailed;
    // This API decodes a copied, non-persisted context. No CMS/chain signature
    // verification or root retrieval is requested. Provenance is the local OS
    // store/cache, never an arbitrary downloaded CMS object.
    const context = CertCreateCTLContext(.{ .CERT = .ASN, .CMSG = .ASN }, encoded.ptr, @intCast(encoded.len)) orelse
        return error.TlsTrustStoreLoadFailed;
    defer _ = CertFreeCTLContext(context);
    try ctl_policy.append(snapshot, kind, context.content[0..context.content_length]);
}

const StoreKind = enum { roots, disallowed, authroot_cache };

fn readStore(snapshot: *metadata.Snapshot, scope: u16, name: [*:0]const u16, kind: StoreKind) Error!void {
    const provider: crypt32.CERT_STORE.PROV = if (kind == .authroot_cache) .SYSTEM_REGISTRY_W else .SYSTEM_W;
    const store = crypt32.CertOpenStore(provider, .{}, .NULL, .{
        .OPEN_EXISTING = true,
        .READONLY = true,
        .Reserved16 = scope,
    }, name) orelse {
        // An absent disallowed store is distinct from an unreadable store.
        const code = @intFromEnum(windows.GetLastError());
        if (kind != .roots and (code == 2 or code == not_found)) return;
        return error.TlsTrustStoreLoadFailed;
    };
    defer _ = crypt32.CertCloseStore(store, .{});
    var ctl: ?*const CtlContext = null;
    defer if (ctl) |current| {
        _ = CertFreeCTLContext(current);
    };
    while (true) {
        ctl = CertEnumCTLsInStore(store, ctl);
        const current = ctl orelse {
            if (@intFromEnum(windows.GetLastError()) != not_found) return error.TlsTrustStoreLoadFailed;
            break;
        };
        try ctl_policy.append(snapshot, if (kind == .disallowed) .disallowed else .authroot, current.content[0..current.content_length]);
    }
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
        const index = try snapshot.add(certificate.pbCertEncoded[0..certificate.cbCertEncoded], kind == .roots);
        const policy = if (kind != .disallowed) try readPolicy(snapshot, certificate) else metadata.Windows{ .roles = 0 };
        const entry = &snapshot.entries.items[index];
        entry.authroot_program = entry.authroot_program or kind == .authroot_cache;
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

const cert_disallowed_filetime_prop_id: u32 = 104;
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
            if (property_id == cert_disallowed_filetime_prop_id and bytes.len == 0) {
                result.unsupported = true;
            } else {
                result.merge(.{ .disallow_at = try filetime(bytes) });
            }
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
    if (!CertGetCertificateContextProperty(certificate, id, if (buffer) |bytes| (if (bytes.len == 0) null else bytes.ptr) else null, &size).toBool()) {
        return if (@intFromEnum(windows.GetLastError()) == not_found) error.Missing else error.Failure;
    }
    return size;
}

fn readProperty(allocator: Allocator, limit: usize, query: Query, id: u32) Error!?[]u8 {
    const needed = query.function(query.context, id, null) catch |err| return switch (err) {
        error.Missing => null,
        error.Failure => error.TlsTrustStoreLoadFailed,
    };
    if (limit == 0 or (needed == 0 and id != cert_disallowed_filetime_prop_id) or needed > limit or needed > std.math.maxInt(u32))
        return error.TlsTrustStoreLoadFailed;
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

test "Windows present empty104 is unsupported rather than absent or a cutoff" {
    const Fake = struct {
        state: enum { absent, empty, value } = .empty,
        fail_read: bool = false,
        changed_size: bool = false,
        empty128: bool = false,

        fn query(context: *const anyopaque, id: u32, buffer: ?[]u8) QueryError!usize {
            const self: *const @This() = @ptrCast(@alignCast(context));
            if (id != 104 and id != 128) return error.Missing;
            if (id == 104 and self.state == .absent) return error.Missing;
            var time: [8]u8 = undefined;
            const seconds: u64 = if (id == 104) 1_800_000_000 else 1_900_000_000;
            std.mem.writeInt(u64, &time, (seconds + 11_644_473_600) * 10_000_000, .little);
            const value: []const u8 = if ((id == 104 and self.state == .empty) or (id == 128 and self.empty128)) "" else &time;
            if (buffer) |bytes| {
                if (self.fail_read) return error.Failure;
                if (self.changed_size and id == 104) return 8;
                if (bytes.len != value.len) return error.Failure;
                @memcpy(bytes, value);
            }
            return value.len;
        }

        fn run(allocator: Allocator) !void {
            const self = @This(){};
            const result = try readPolicyProperties(allocator, 16, .{ .context = &self, .function = query }, 1);
            try std.testing.expect(result.unsupported);
            try std.testing.expectEqual(@as(u2, 1), result.roles);
            try std.testing.expectEqual(@as(?i64, 1_900_000_000), result.disallow_at);
        }
    };
    inline for (.{ .absent, .empty, .value }) |state| {
        const fake = Fake{ .state = state };
        const result = try readPolicyProperties(std.testing.allocator, 16, .{ .context = &fake, .function = Fake.query }, 1);
        try std.testing.expectEqual(state == .empty, result.unsupported);
        try std.testing.expectEqual(@as(?i64, if (state == .value) 1_800_000_000 else 1_900_000_000), result.disallow_at);
        try std.testing.expectEqual(state != .empty, result.permits(.{
            .role = .server,
            .identity = null,
            .now_seconds = 1_700_000_000,
            .issuer = true,
            .self_issued = true,
        }));
    }
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Fake.run, .{});
    for ([_]Fake{ .{ .fail_read = true }, .{ .changed_size = true }, .{ .empty128 = true } }) |fake| {
        try std.testing.expectError(error.TlsTrustStoreLoadFailed, readPolicyProperties(std.testing.allocator, 16, .{ .context = &fake, .function = Fake.query }, 1));
    }
    const empty = Fake{};
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, readProperty(std.testing.allocator, 0, .{ .context = &empty, .function = Fake.query }, 104));
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

test "Windows registry CTL payload rejects wrong types and inconsistent sizes" {
    var buffer: [16]u8 align(@alignOf(windows.KEY.VALUE.PARTIAL_INFORMATION)) = @splat(0);
    std.mem.writeInt(u32, buffer[4..8], 3, .little);
    std.mem.writeInt(u32, buffer[8..12], 4, .little);
    @memcpy(buffer[12..], "data");
    try std.testing.expectEqualStrings("data", try registryPayload(&buffer));
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, registryPayload(buffer[0..8]));
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, registryPayload(buffer[0..12]));
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, registryPayload(buffer[0..15]));
    std.mem.writeInt(u32, buffer[4..8], 1, .little);
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, registryPayload(&buffer));
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

test "native Windows CTL decoding owns restrictions after releasing process-local CMS data" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const fixtures = @import("ctl_fixtures.zig");
    var snapshot = metadata.Snapshot.init(std.testing.allocator, .{});
    defer snapshot.deinit();
    {
        const content = try fixtures.content(std.testing.allocator, .{
            .entries = &.{.{ .identifier = &@as([20]u8, @splat(1)) }},
        });
        defer std.testing.allocator.free(content);
        const encoded = try fixtures.envelope(std.testing.allocator, content);
        defer std.testing.allocator.free(encoded);
        try appendEncodedCtl(&snapshot, .authroot, encoded);
    }
    try std.testing.expectEqual(@as(usize, 0), snapshot.entries.items.len);
    try std.testing.expectEqual(@as(usize, 1), snapshot.fingerprint_entries);
    try std.testing.expectEqualSlices(u8, &@as([20]u8, @splat(1)), snapshot.fingerprint_lists.items[0].entries[0].identifier[0..20]);
}

test "native Windows CTL empty104 stays present and preserves an independent restriction" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const Probe = struct {
        const Blob = extern struct { size: u32, data: [*]const u8 };
        const Attribute = extern struct { oid: [*:0]const u8, count: u32, values: [*]const Blob };
        const Entry = extern struct { identifier: Blob, count: u32, attributes: [*]const Attribute };
        const State = enum { absent, empty, known_fixture_value, other_value, other_length, query_error };
        const Observation = struct { state: State, length: u32 = 0, code: u32 = 0 };

        extern "crypt32" fn CertSetCertificateContextPropertiesFromCTLEntry(
            *const crypt32.CERT_CONTEXT,
            *const Entry,
            u32,
        ) callconv(.winapi) windows.BOOL;

        fn apply(certificate: *const crypt32.CERT_CONTEXT, identifier: *const [20]u8, attributes: []const Attribute) bool {
            const entry: Entry = .{
                .identifier = .{ .size = identifier.len, .data = identifier },
                .count = @intCast(attributes.len),
                .attributes = attributes.ptr,
            };
            return CertSetCertificateContextPropertiesFromCTLEntry(certificate, &entry, 0).toBool();
        }

        fn observe(certificate: *const crypt32.CERT_CONTEXT, id: u32, expected: *const [8]u8) Observation {
            var length: u32 = 0;
            if (!CertGetCertificateContextProperty(certificate, id, null, &length).toBool()) {
                const code = @intFromEnum(windows.GetLastError());
                return .{ .state = if (code == not_found) .absent else .query_error, .code = code };
            }
            if (length == 0) return .{ .state = .empty };
            if (length != 8) return .{ .state = .other_length, .length = length };
            var bytes: [8]u8 = undefined;
            if (!CertGetCertificateContextProperty(certificate, id, &bytes, &length).toBool())
                return .{ .state = .query_error, .code = @intFromEnum(windows.GetLastError()) };
            if (length != 8) return .{ .state = .other_length, .length = length };
            return .{ .state = if (std.mem.eql(u8, &bytes, expected)) .known_fixture_value else .other_value, .length = length };
        }
    };
    const fixtures = @import("trust_fixtures.zig");
    var chain = try fixtures.Chain.init(std.testing.allocator, .ecdsa_p256);
    defer chain.deinit();
    // Never open a store or add this leaf to one. CTL projection changes only
    // this fresh context's in-process properties; freeing it discards them.
    const certificate = CertCreateCertificateContext(.{ .CERT = .ASN }, chain.leaf.ptr, @intCast(chain.leaf.len)) orelse
        return error.TlsTrustStoreLoadFailed;
    defer _ = crypt32.CertFreeCertificateContext(certificate);
    var selected = @import("crypto/standard.zig").StandardProvider.init(std.testing.io, std.testing.allocator);
    var identifier: [20]u8 = undefined;
    {
        var hash = try selected.provider().hashCreate(std.testing.allocator, .sha1);
        defer hash.deinit();
        try hash.update(chain.leaf);
        try hash.snapshot(&identifier);
    }
    var time: [8]u8 = undefined;
    std.mem.writeInt(u64, &time, @as(u64, 1_800_000_000 + 11_644_473_600) * 10_000_000, .little);
    var encoded: [10]u8 = undefined;
    @memcpy(encoded[0..2], "\x04\x08");
    @memcpy(encoded[2..], &time);
    const full = [_]Probe.Blob{.{ .size = encoded.len, .data = &encoded }};
    const empty = [_]Probe.Blob{.{ .size = 2, .data = "\x04\x00" }};
    const time_attribute: Probe.Attribute = .{ .oid = "1.3.6.1.4.1.311.10.11.104", .count = 1, .values = &full };
    const empty_attribute: Probe.Attribute = .{ .oid = time_attribute.oid, .count = 1, .values = &empty };
    const other_attribute: Probe.Attribute = .{ .oid = "1.3.6.1.4.1.311.10.11.128", .count = 1, .values = &full };
    try std.testing.expectEqual(Probe.State.absent, Probe.observe(certificate, 104, &time).state);
    try std.testing.expectEqual(Probe.State.absent, Probe.observe(certificate, 128, &time).state);

    try std.testing.expect(Probe.apply(certificate, &identifier, &.{empty_attribute}));
    try std.testing.expectEqual(Probe.State.empty, Probe.observe(certificate, 104, &time).state);
    try std.testing.expectEqual(Probe.State.absent, Probe.observe(certificate, 128, &time).state);
    try std.testing.expect(Probe.apply(certificate, &identifier, &.{ time_attribute, other_attribute }));
    try std.testing.expectEqual(Probe.State.known_fixture_value, Probe.observe(certificate, 104, &time).state);
    try std.testing.expectEqual(Probe.State.known_fixture_value, Probe.observe(certificate, 128, &time).state);

    try std.testing.expect(Probe.apply(certificate, &identifier, &.{other_attribute}));
    try std.testing.expectEqual(Probe.State.known_fixture_value, Probe.observe(certificate, 104, &time).state);
    try std.testing.expectEqual(Probe.State.known_fixture_value, Probe.observe(certificate, 128, &time).state);

    try std.testing.expect(Probe.apply(certificate, &identifier, &.{empty_attribute}));
    try std.testing.expectEqual(Probe.State.empty, Probe.observe(certificate, 104, &time).state);
    try std.testing.expectEqual(Probe.State.known_fixture_value, Probe.observe(certificate, 128, &time).state);
    try std.testing.expect(Probe.apply(certificate, &identifier, &.{empty_attribute}));
    try std.testing.expectEqual(Probe.State.empty, Probe.observe(certificate, 104, &time).state);
    try std.testing.expectEqual(Probe.State.known_fixture_value, Probe.observe(certificate, 128, &time).state);
    const result = try readPolicyProperties(std.testing.allocator, 4096, .{ .context = certificate, .function = queryProperty }, 3);
    try std.testing.expect(result.unsupported);
    try std.testing.expectEqual(@as(?i64, 1_800_000_000), result.disallow_at);
}
