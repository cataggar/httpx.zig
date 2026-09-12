//! Public Security/CoreFoundation discovery APIs only. No SecTrust evaluation.
const std = @import("std");
const builtin = @import("builtin");
const metadata = @import("platform_trust.zig");
const Error = @import("trust.zig").TrustError;
const Allocator = std.mem.Allocator;
const Ref = *const anyopaque;
const Index = isize;

extern "Security" fn SecTrustCopyAnchorCertificates(*?Ref) i32;
extern "Security" fn SecTrustSettingsCopyCertificates(u32, *?Ref) i32;
extern "Security" fn SecTrustSettingsCopyTrustSettings(Ref, u32, *?Ref) i32;
extern "Security" fn SecCertificateCopyData(Ref) ?Ref;
extern "Security" fn SecCertificateGetTypeID() usize;
extern "Security" fn SecPolicyGetTypeID() usize;
extern "Security" fn SecPolicyCopyProperties(Ref) ?Ref;
extern "Security" const kSecPolicyOid: Ref;
extern "Security" const kSecPolicyName: Ref;
extern "Security" const kSecPolicyClient: Ref;
extern "Security" const kSecPolicyAppleSSL: Ref;
extern "CoreFoundation" fn CFRelease(Ref) void;
extern "CoreFoundation" fn CFEqual(Ref, Ref) u8;
extern "CoreFoundation" fn CFGetTypeID(Ref) usize;
extern "CoreFoundation" fn CFArrayGetTypeID() usize;
extern "CoreFoundation" fn CFArrayGetCount(Ref) Index;
extern "CoreFoundation" fn CFArrayGetValueAtIndex(Ref, Index) ?Ref;
extern "CoreFoundation" fn CFDictionaryGetTypeID() usize;
extern "CoreFoundation" fn CFDictionaryGetCount(Ref) Index;
extern "CoreFoundation" fn CFDictionaryGetValue(Ref, Ref) ?Ref;
extern "CoreFoundation" fn CFDictionaryGetKeysAndValues(Ref, [*]?Ref, ?[*]?Ref) void;
extern "CoreFoundation" fn CFDataGetTypeID() usize;
extern "CoreFoundation" fn CFDataGetLength(Ref) Index;
extern "CoreFoundation" fn CFDataGetBytePtr(Ref) ?[*]const u8;
extern "CoreFoundation" fn CFStringGetTypeID() usize;
extern "CoreFoundation" fn CFStringGetLength(Ref) Index;
extern "CoreFoundation" fn CFStringCreateWithBytes(?Ref, [*]const u8, Index, u32, u8) ?Ref;
extern "CoreFoundation" fn CFStringGetCString(Ref, [*]u8, Index, u32) u8;
extern "CoreFoundation" fn CFNumberGetTypeID() usize;
extern "CoreFoundation" fn CFNumberGetValue(Ref, Index, *anyopaque) u8;
extern "CoreFoundation" fn CFBooleanGetTypeID() usize;
extern "CoreFoundation" fn CFBooleanGetValue(Ref) u8;

pub fn load(allocator: Allocator, limits: metadata.Limits) Error!metadata.Snapshot {
    if (comptime builtin.os.tag != .macos) return error.TlsTrustStoreLoadFailed;
    var snapshot = metadata.Snapshot.init(allocator, limits);
    errdefer snapshot.deinit();
    var keys = try Keys.init();
    defer keys.deinit();
    var roots: ?Ref = null;
    const status = SecTrustCopyAnchorCertificates(&roots);
    defer if (roots) |value| CFRelease(value);
    if (status != 0 or roots == null) return error.TlsTrustStoreLoadFailed;
    try readCertificates(&snapshot, keys, roots.?, true);
    for (0..3) |domain| {
        var certificates: ?Ref = null;
        const domain_status = SecTrustSettingsCopyCertificates(@intCast(domain), &certificates);
        defer if (certificates) |value| CFRelease(value);
        if (domain_status == -25263 and certificates == null) continue; // errSecNoTrustSettings
        if (domain_status != 0 or certificates == null) return error.TlsTrustStoreLoadFailed;
        try readCertificates(&snapshot, keys, certificates.?, false);
    }
    return snapshot;
}

fn readCertificates(snapshot: *metadata.Snapshot, keys: Keys, certificates: Ref, defaults: bool) Error!void {
    const count = try arrayCount(certificates, snapshot.limits.max_certificates);
    for (0..count) |i| {
        const certificate = CFArrayGetValueAtIndex(certificates, @intCast(i)) orelse return error.TlsTrustStoreLoadFailed;
        try expectType(certificate, SecCertificateGetTypeID());
        const data = SecCertificateCopyData(certificate) orelse return error.TlsTrustStoreLoadFailed;
        defer CFRelease(data);
        try expectType(data, CFDataGetTypeID());
        const size = try boundedCount(CFDataGetLength(data), snapshot.limits.max_certificate_bytes);
        const bytes = CFDataGetBytePtr(data) orelse return error.TlsTrustStoreLoadFailed;
        const index = try snapshot.add(bytes[0..size], defaults);
        for (0..3) |domain| {
            if (snapshot.entries.items[index].domains[domain] != null) continue;
            var settings: ?Ref = null;
            const status = SecTrustSettingsCopyTrustSettings(certificate, @intCast(domain), &settings);
            defer if (settings) |value| CFRelease(value);
            if (status == -25300 and settings == null) continue; // errSecItemNotFound
            if (status != 0 or settings == null) return error.TlsTrustStoreLoadFailed;
            try readSettings(snapshot, keys, index, domain, settings.?);
        }
    }
}

fn readSettings(snapshot: *metadata.Snapshot, keys: Keys, index: usize, domain: usize, settings: Ref) Error!void {
    const count = try arrayCount(settings, snapshot.limits.max_rules_per_domain);
    const rules = try snapshot.allocator.alloc(metadata.Rule, count);
    defer snapshot.allocator.free(rules);
    var candidate = count == 0;
    for (rules, 0..) |*rule, i| {
        const dictionary = CFArrayGetValueAtIndex(settings, @intCast(i)) orelse return error.TlsTrustStoreLoadFailed;
        rule.* = try readRule(keys, dictionary);
        candidate = candidate or rule.result == .trust_root or rule.result == .trust_as_root;
    }
    try snapshot.setDomain(index, domain, rules);
    snapshot.entries.items[index].anchor_candidate = snapshot.entries.items[index].anchor_candidate or candidate;
}

const Key = enum(usize) { policy, application, hostname, key_usage, allowed_error, result };
const Keys = struct {
    values: [6]Ref,

    fn init() Error!Keys {
        const names = [_][]const u8{
            "kSecTrustSettingsPolicy",       "kSecTrustSettingsApplication",
            "kSecTrustSettingsPolicyString", "kSecTrustSettingsKeyUsage",
            "kSecTrustSettingsAllowedError", "kSecTrustSettingsResult",
        };
        var self: Keys = undefined;
        var initialized: usize = 0;
        errdefer for (self.values[0..initialized]) |value| CFRelease(value);
        for (names, 0..) |name, i| {
            self.values[i] = CFStringCreateWithBytes(null, name.ptr, @intCast(name.len), 0x08000100, 0) orelse
                return error.TlsTrustStoreLoadFailed;
            initialized += 1;
        }
        return self;
    }

    fn deinit(self: Keys) void {
        for (self.values) |value| CFRelease(value);
    }

    fn get(self: Keys, dictionary: Ref, key: Key) ?Ref {
        return CFDictionaryGetValue(dictionary, self.values[@intFromEnum(key)]);
    }
};

fn readRule(keys: Keys, dictionary: Ref) Error!metadata.Rule {
    var rule = metadata.Rule{};
    if (!try knownKeys(dictionary, &keys.values)) rule.unsupported = true;
    if (keys.get(dictionary, .result)) |value| {
        rule.result = switch (try integer(value)) {
            1 => .trust_root,
            2 => .trust_as_root,
            3 => .deny,
            4 => .unspecified,
            else => return error.TlsTrustStoreLoadFailed,
        };
    }
    if (keys.get(dictionary, .key_usage)) |value| {
        const usage = try integer(value);
        if (usage == -1 or usage == 0xffffffff) {
            rule.key_usage = 0xffffffff;
        } else if (usage >= 0 and usage <= 0x3f) {
            rule.key_usage = @intCast(usage);
        } else {
            rule.unsupported = true;
        }
    }
    // Application code-identity constraints and error waivers are explicitly
    // unsupported, rather than being erased when projecting settings to DER.
    if (keys.get(dictionary, .application) != null or keys.get(dictionary, .allowed_error) != null)
        rule.unsupported = true;
    if (keys.get(dictionary, .hostname)) |value| try hostname(&rule, value);
    if (keys.get(dictionary, .policy)) |value| try readPolicy(&rule, value);
    return rule;
}

fn readPolicy(rule: *metadata.Rule, policy: Ref) Error!void {
    try expectType(policy, SecPolicyGetTypeID());
    const properties = SecPolicyCopyProperties(policy) orelse return error.TlsTrustStoreLoadFailed;
    defer CFRelease(properties);
    if (!try knownKeys(properties, &.{ kSecPolicyOid, kSecPolicyName, kSecPolicyClient }))
        rule.unsupported = true;
    const oid = CFDictionaryGetValue(properties, kSecPolicyOid) orelse return error.TlsTrustStoreLoadFailed;
    try expectType(oid, CFStringGetTypeID());
    if (CFEqual(oid, kSecPolicyAppleSSL) == 0) {
        rule.unsupported = true;
        return;
    }
    rule.roles = 1;
    if (CFDictionaryGetValue(properties, kSecPolicyClient)) |client| {
        try expectType(client, CFBooleanGetTypeID());
        if (CFBooleanGetValue(client) != 0) rule.roles = 2;
    }
    if (CFDictionaryGetValue(properties, kSecPolicyName)) |name| try hostname(rule, name);
}

fn knownKeys(dictionary: Ref, known: []const Ref) Error!bool {
    try expectType(dictionary, CFDictionaryGetTypeID());
    const count = try boundedCount(CFDictionaryGetCount(dictionary), 64);
    var keys: [64]?Ref = @splat(null);
    CFDictionaryGetKeysAndValues(dictionary, &keys, null);
    for (keys[0..count]) |maybe_key| {
        const key = maybe_key orelse return error.TlsTrustStoreLoadFailed;
        var recognized = false;
        for (known) |expected| {
            if (CFEqual(key, expected) != 0) recognized = true;
        }
        if (!recognized) return false;
    }
    return true;
}

fn hostname(rule: *metadata.Rule, value: Ref) Error!void {
    try expectType(value, CFStringGetTypeID());
    const length = try boundedCount(CFStringGetLength(value), 254);
    var buffer: [255]u8 = @splat(0);
    if (CFStringGetCString(value, &buffer, buffer.len, 0x0600) == 0) return error.TlsTrustStoreLoadFailed; // ASCII
    const end = std.mem.indexOfScalar(u8, &buffer, 0) orelse return error.TlsTrustStoreLoadFailed;
    if (end != length) return error.TlsTrustStoreLoadFailed;
    try rule.setHostname(buffer[0..end]);
}

fn integer(value: Ref) Error!i64 {
    try expectType(value, CFNumberGetTypeID());
    var result: i64 = 0;
    if (CFNumberGetValue(value, 4, &result) == 0) return error.TlsTrustStoreLoadFailed; // kCFNumberSInt64Type
    return result;
}

fn expectType(value: Ref, expected: usize) Error!void {
    if (CFGetTypeID(value) != expected) return error.TlsTrustStoreLoadFailed;
}

fn arrayCount(array: Ref, limit: usize) Error!usize {
    try expectType(array, CFArrayGetTypeID());
    return boundedCount(CFArrayGetCount(array), limit);
}

fn boundedCount(count: Index, limit: usize) Error!usize {
    if (count < 0 or @as(usize, @intCast(count)) > limit) return error.TlsTrustStoreLoadFailed;
    return @intCast(count);
}

test "macOS native counts cannot become unbounded allocations" {
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, boundedCount(-1, 10));
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, boundedCount(11, 10));
    try std.testing.expectEqual(@as(usize, 10), try boundedCount(10, 10));
}

extern "CoreFoundation" fn CFDictionaryCreateMutable(?Ref, Index, ?Ref, ?Ref) ?Ref;
extern "CoreFoundation" fn CFDictionarySetValue(Ref, Ref, Ref) void;
extern "CoreFoundation" fn CFNumberCreate(?Ref, Index, *const anyopaque) ?Ref;

test "native macOS in-memory settings parse deny and reject a malformed value without store mutation" {
    if (comptime builtin.os.tag != .macos) return error.SkipZigTest;
    const keys = try Keys.init();
    defer keys.deinit();
    // Null callbacks are safe here: the test holds every key/value alive.
    const dictionary = CFDictionaryCreateMutable(null, 0, null, null) orelse return error.OutOfMemory;
    defer CFRelease(dictionary);
    const deny: i64 = 3;
    const number = CFNumberCreate(null, 4, &deny) orelse return error.OutOfMemory;
    defer CFRelease(number);
    CFDictionarySetValue(dictionary, keys.values[@intFromEnum(Key.result)], number);
    try std.testing.expectEqual(metadata.Result.deny, (try readRule(keys, dictionary)).result);
    CFDictionarySetValue(dictionary, keys.values[@intFromEnum(Key.result)], keys.values[0]);
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, readRule(keys, dictionary));
}
