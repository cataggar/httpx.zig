//! Owned, immutable OS trust metadata. No platform certificate verification.
const std = @import("std");
const trust = @import("trust.zig");
const crypto = @import("crypto/provider.zig");
const metadata_digest = @import("metadata_digest.zig");
const disallowed = @import("windows_disallowed.zig");
const Error = trust.TrustError;
const Allocator = std.mem.Allocator;

pub const Limits = struct {
    max_certificates: usize = 8192,
    max_certificate_bytes: usize = 256 * 1024,
    max_der_bytes: usize = 32 * 1024 * 1024,
    max_rules_per_domain: usize = 64,
    max_property_bytes: usize = 64 * 1024,
    max_fingerprint_lists: usize = 8,
    max_fingerprint_entries: usize = 16384,
    max_ctl_bytes: usize = 16 * 1024 * 1024,
};

pub const Use = struct {
    role: trust.PeerRole,
    identity: ?trust.PeerIdentity,
    now_seconds: i64,
    issuer: bool,
    self_issued: bool,
    anchor: bool = false,
    custom_anchor: bool = false,
};

pub const Decision = enum { deny, chain_only, anchor, self_signed_anchor };

pub const Windows = struct {
    roles: u2 = 3,
    denied_roles: u2 = 0,
    /// Conservatively disallow all use at the earliest platform cutoff,
    /// including previously issued certificates (stricter than issuance-only rules).
    disallow_at: ?i64 = null,
    unsupported: bool = false,

    pub fn merge(self: *Windows, other: Windows) void {
        self.roles &= other.roles;
        self.denied_roles |= other.denied_roles;
        self.unsupported = self.unsupported or other.unsupported;
        if (other.disallow_at) |cutoff|
            self.disallow_at = if (self.disallow_at) |old| @min(old, cutoff) else cutoff;
    }

    pub fn permits(self: Windows, use: Use) bool {
        const role: u2 = if (use.role == .server) 1 else 2;
        return !self.unsupported and self.roles & role != 0 and self.denied_roles & role == 0 and
            (self.disallow_at == null or use.now_seconds < self.disallow_at.?);
    }
};

pub const Result = enum { trust_root, trust_as_root, deny, unspecified };

pub const Rule = struct {
    result: Result = .trust_root,
    roles: u2 = 3,
    key_usage: u32 = 0xffffffff,
    hostname: [254]u8 = @splat(0),
    hostname_len: u8 = 0,
    unsupported: bool = false,

    pub fn setHostname(self: *Rule, name: []const u8) Error!void {
        if (name.len == 0 or name.len > self.hostname.len) return error.TlsTrustStoreLoadFailed;
        for (name) |byte| {
            if (byte < 0x21 or byte > 0x7e or byte == '*') return error.TlsTrustStoreLoadFailed;
        }
        if (self.hostname_len != 0 and !std.ascii.eqlIgnoreCase(self.hostname[0..self.hostname_len], name)) {
            self.unsupported = true;
            return;
        }
        @memcpy(self.hostname[0..name.len], name);
        self.hostname_len = @intCast(name.len);
    }

    fn matches(self: Rule, use: Use) bool {
        const role: u2 = if (use.role == .server) 1 else 2;
        const key_usage: u32 = if (use.issuer) 8 else 1;
        if (self.roles & role == 0 or self.key_usage & key_usage == 0) return false;
        if (self.hostname_len == 0) return true;
        const identity = use.identity orelse return false;
        const name = self.hostname[0..self.hostname_len];
        return switch (identity) {
            .dns_name => |expected| std.ascii.eqlIgnoreCase(trimDot(name), trimDot(expected)),
            .ip_address => |expected| blk: {
                const parsed = std.Io.net.IpAddress.parse(name, 0) catch break :blk false;
                break :blk switch (expected) {
                    .v4 => |ip| parsed == .ip4 and std.mem.eql(u8, &ip, &parsed.ip4.bytes),
                    .v6 => |ip| parsed == .ip6 and std.mem.eql(u8, &ip, &parsed.ip6.bytes),
                };
            },
        };
    }
};

fn trimDot(name: []const u8) []const u8 {
    return if (name.len != 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
}

pub const Entry = struct {
    der: []u8,
    anchor_candidate: bool = false,
    authroot_program: bool = false,
    windows: ?Windows = null,
    /// User, administrator, system. Null is absent; empty is unconditional trustRoot.
    domains: [3]?[]Rule = .{ null, null, null },

    pub fn decide(self: Entry, use: Use) Decision {
        if (self.windows) |windows| {
            if (!windows.permits(use)) return .deny;
        }
        for (self.domains, 0..) |maybe_rules, domain| {
            const rules = maybe_rules orelse continue;
            const decision = decideRules(rules, use);
            if (decision == .chain_only) {
                // Unspecified never creates trust or masks a lower-domain deny.
                for (self.domains[domain + 1 ..]) |lower| {
                    if (lower) |lower_rules| {
                        for (lower_rules) |rule| {
                            if (rule.unsupported or (rule.result == .deny and rule.matches(use))) return .deny;
                        }
                    }
                }
            }
            return decision;
        }
        return if (self.anchor_candidate or self.windows != null or self.authroot_program) .anchor else .chain_only;
    }

    fn decideRules(rules: []const Rule, use: Use) Decision {
        if (rules.len == 0) return if (use.self_issued) .self_signed_anchor else .deny;
        var result: Decision = .deny;
        for (rules) |rule| {
            // Unknown application/policy constraints cannot be treated as a
            // nonmatching rule and accidentally reveal a broader grant.
            if (rule.unsupported) return .deny;
            if (!rule.matches(use)) continue;
            switch (rule.result) {
                .deny => return .deny,
                .trust_root => {
                    if (!use.self_issued) return .deny;
                    result = .self_signed_anchor;
                },
                .trust_as_root => {
                    if (use.self_issued) return .deny;
                    result = .anchor;
                },
                .unspecified => if (result == .deny) {
                    result = .chain_only;
                },
            }
        }
        // A present but nonmatching higher-domain record is not broadened
        // into an unrestricted grant from a lower domain.
        return result;
    }
};

/// A restriction lookup key, never a source of trust anchors. Native CTL
/// decoding must reject unsupported identifier forms before constructing it.
pub const FingerprintEntry = struct {
    identifier: [64]u8 = @splat(0),
    identifier_length: u8 = 0,
    policy: Windows,
    sha256: ?[32]u8 = null,

    pub fn init(algorithm: crypto.HashAlgorithm, identifier: []const u8, policy: Windows) Error!FingerprintEntry {
        if (identifier.len != algorithm.digestLength()) return error.TlsTrustStoreLoadFailed;
        var result = FingerprintEntry{ .policy = policy, .identifier_length = @intCast(identifier.len) };
        @memcpy(result.identifier[0..identifier.len], identifier);
        return result;
    }

    pub fn initDisallowed(identifier: []const u8) Error!FingerprintEntry {
        if (!validDisallowedLength(identifier.len)) return error.TlsTrustStoreLoadFailed;
        var result = FingerprintEntry{ .policy = .{ .roles = 0 }, .identifier_length = @intCast(identifier.len) };
        @memcpy(result.identifier[0..identifier.len], identifier);
        return result;
    }

    pub fn bytes(self: *const FingerprintEntry) []const u8 {
        return self.identifier[0..self.identifier_length];
    }
};

pub const FingerprintList = struct {
    pub const Kind = enum { constraints, authroot, disallowed };
    pub const Identity = enum { certificate_der, windows_disallowed };
    kind: Kind = .constraints,
    identity: Identity = .certificate_der,
    algorithm: ?crypto.HashAlgorithm = null,
    this_update: i64,
    next_update: ?i64 = null,
    entries: []const FingerprintEntry,
};

fn validDisallowedLength(length: usize) bool {
    // Validate possible digest widths without assigning an algorithm/domain to
    // any identifier. In particular, 16 and 48 are not identity selectors.
    return switch (length) {
        16, 20, 32, 48, 64 => true,
        else => false,
    };
}

fn lowerBound(entries: []const FingerprintEntry, digest: []const u8) usize {
    var low: usize = 0;
    var high = entries.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        if (std.mem.order(u8, entries[mid].bytes(), digest) == .lt)
            low = mid + 1
        else
            high = mid;
    }
    return low;
}

fn contains(entries: []const FingerprintEntry, digest: []const u8) bool {
    const index = lowerBound(entries, digest);
    return index < entries.len and std.mem.eql(u8, entries[index].bytes(), digest);
}

pub const Snapshot = struct {
    allocator: Allocator,
    limits: Limits,
    entries: std.ArrayList(Entry) = .empty,
    der_bytes: usize = 0,
    fingerprint_lists: std.ArrayList(FingerprintList) = .empty,
    fingerprint_entries: usize = 0,

    pub fn init(allocator: Allocator, limits: Limits) Snapshot {
        return .{ .allocator = allocator, .limits = limits };
    }

    pub fn deinit(self: *Snapshot) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.der);
            for (entry.domains) |rules| if (rules) |owned| self.allocator.free(owned);
        }
        self.entries.deinit(self.allocator);
        for (self.fingerprint_lists.items) |list| self.allocator.free(list.entries);
        self.fingerprint_lists.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn add(self: *Snapshot, der: []const u8, anchor_candidate: bool) Error!usize {
        if (der.len == 0 or der.len > self.limits.max_certificate_bytes)
            return error.TlsTrustStoreLoadFailed;
        for (self.entries.items, 0..) |*entry, index| {
            if (std.mem.eql(u8, entry.der, der)) {
                entry.anchor_candidate = entry.anchor_candidate or anchor_candidate;
                return index;
            }
        }
        if (self.entries.items.len >= self.limits.max_certificates or
            der.len > self.limits.max_der_bytes - self.der_bytes) return error.TlsTrustStoreLoadFailed;
        const owned = try self.allocator.dupe(u8, der);
        errdefer self.allocator.free(owned);
        try self.entries.append(self.allocator, .{ .der = owned, .anchor_candidate = anchor_candidate });
        self.der_bytes += der.len;
        return self.entries.items.len - 1;
    }

    pub fn setDomain(self: *Snapshot, index: usize, domain: usize, rules: []const Rule) Error!void {
        if (index >= self.entries.items.len or domain >= 3 or rules.len > self.limits.max_rules_per_domain or
            self.entries.items[index].domains[domain] != null) return error.TlsTrustStoreLoadFailed;
        self.entries.items[index].domains[domain] = try self.allocator.dupe(Rule, rules);
    }

    pub fn decide(self: Snapshot, der: []const u8, use: Use) Decision {
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.der, der)) return entry.decide(use);
        }
        return .anchor; // No platform restriction on a custom/peer certificate.
    }

    /// Copies all retained data. Adding hashes does not add an Entry or anchor.
    pub fn addFingerprintList(self: *Snapshot, list: FingerprintList) Error!void {
        if (self.fingerprint_lists.items.len >= self.limits.max_fingerprint_lists or
            list.entries.len > self.limits.max_fingerprint_entries - self.fingerprint_entries or
            (list.next_update != null and list.next_update.? < list.this_update))
            return error.TlsTrustStoreLoadFailed;
        switch (list.identity) {
            .certificate_der => if (list.algorithm == null) return error.TlsTrustStoreLoadFailed,
            .windows_disallowed => if (list.kind != .disallowed or list.algorithm != null)
                return error.TlsTrustStoreLoadFailed,
        }
        for (list.entries) |entry| {
            if (entry.identifier_length > entry.identifier.len) return error.TlsTrustStoreLoadFailed;
            switch (list.identity) {
                .certificate_der => if (entry.identifier_length != list.algorithm.?.digestLength())
                    return error.TlsTrustStoreLoadFailed,
                .windows_disallowed => if (!validDisallowedLength(entry.identifier_length))
                    return error.TlsTrustStoreLoadFailed,
            }
        }
        const entries = try self.allocator.dupe(FingerprintEntry, list.entries);
        errdefer self.allocator.free(entries);
        std.mem.sort(FingerprintEntry, entries, {}, struct {
            fn lessThan(_: void, a: FingerprintEntry, b: FingerprintEntry) bool {
                return std.mem.order(u8, a.bytes(), b.bytes()) == .lt;
            }
        }.lessThan);
        var owned = list;
        owned.entries = entries;
        try self.fingerprint_lists.append(self.allocator, owned);
        self.fingerprint_entries += entries.len;
    }

    pub fn check(
        self: *const Snapshot,
        certificate_der: []const u8,
        use: Use,
        hasher: ?metadata_digest.MetadataDigest,
        scratch: Allocator,
    ) Error!Decision {
        const decision = self.decide(certificate_der, use);
        if (decision == .deny) return decision;
        var digests: Digests = .{
            .hasher = hasher,
            .scratch = scratch,
            .input = certificate_der,
            .certificate_limit = self.limits.max_certificate_bytes,
        };
        defer crypto.secureWipeValue(&digests.values);
        var requires_membership = false;
        if (use.anchor and !use.custom_anchor) {
            for (self.entries.items) |entry| {
                if (entry.authroot_program and std.mem.eql(u8, entry.der, certificate_der))
                    requires_membership = true;
            }
        }
        var has_authroot = false;
        for (self.fingerprint_lists.items) |list| {
            if (use.now_seconds < list.this_update or
                (list.next_update != null and use.now_seconds > list.next_update.?))
                return error.TlsTrustStoreLoadFailed;
            const authroot = list.kind == .authroot;
            has_authroot = has_authroot or authroot;
            if (list.identity == .windows_disallowed) {
                const inputs = try digests.identityInputs();
                if (contains(list.entries, try digests.getDomain(.md5, .public_key_bits))) return .deny;
                if (contains(list.entries, try digests.getDomain(inputs.signature_hash, .tbs_der))) return .deny;
                // Even an empty list requires both identities before allowing.
                continue;
            }
            if (list.entries.len == 0) {
                if (authroot and requires_membership) return .deny;
                continue;
            }
            const digest = try digests.get(list.algorithm.?);
            var low = lowerBound(list.entries, digest);
            var matched = false;
            while (low < list.entries.len and std.mem.eql(u8, list.entries[low].bytes(), digest)) : (low += 1) {
                matched = true;
                const entry = list.entries[low];
                if (list.kind == .disallowed) return .deny;
                if (!entry.policy.permits(use)) return .deny;
                if (entry.sha256) |expected| {
                    if (!std.mem.eql(u8, &expected, try digests.get(.sha256))) return .deny;
                }
            }
            if (authroot and requires_membership and !matched) return .deny;
        }
        if (requires_membership and !has_authroot) return error.TlsTrustStoreLoadFailed;
        return decision;
    }
};

const Digests = struct {
    const Domain = enum { certificate_der, tbs_der, public_key_bits };
    const capacity = blk: {
        var count: usize = 0;
        for (std.enums.values(crypto.HashAlgorithm)) |algorithm|
            count = @max(count, @as(usize, @intFromEnum(algorithm)) + 1);
        break :blk count;
    };

    hasher: ?metadata_digest.MetadataDigest,
    scratch: Allocator,
    input: []const u8,
    certificate_limit: usize = 256 * 1024,
    inputs: ?disallowed.Inputs = null,
    values: [std.enums.values(Domain).len][capacity][64]u8 = undefined,
    ready: [std.enums.values(Domain).len][capacity]bool = @splat(@splat(false)),

    fn get(self: *Digests, algorithm: crypto.HashAlgorithm) Error![]const u8 {
        return self.getDomain(algorithm, .certificate_der);
    }

    fn identityInputs(self: *Digests) Error!disallowed.Inputs {
        if (self.inputs == null) {
            if (self.input.len == 0 or self.input.len > self.certificate_limit) return error.TlsTrustStoreLoadFailed;
            self.inputs = try disallowed.parse(self.input);
        }
        return self.inputs.?;
    }

    fn getDomain(self: *Digests, algorithm: crypto.HashAlgorithm, domain: Domain) Error![]const u8 {
        const index = @intFromEnum(algorithm);
        const domain_index = @intFromEnum(domain);
        const output = self.values[domain_index][index][0..algorithm.digestLength()];
        if (!self.ready[domain_index][index]) {
            const input = switch (domain) {
                .certificate_der => self.input,
                .tbs_der => (try self.identityInputs()).tbs_der,
                .public_key_bits => (try self.identityInputs()).public_key_bits,
            };
            const hasher = self.hasher orelse return error.TlsInvalidTrustConfiguration;
            hasher.hash(self.scratch, algorithm, input, output) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.TlsTrustStoreLoadFailed,
            };
            self.ready[domain_index][index] = true;
        }
        return output;
    }
};

test "platform digest cache covers ABI2 tags for one fixed certificate DER input" {
    const Fake = struct {
        calls: [5]usize = @splat(0),

        fn hash(context: *anyopaque, _: Allocator, algorithm: crypto.HashAlgorithm, input: []const u8, output: []u8) crypto.ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, input, "fixed certificate DER")) return error.InvalidInput;
            self.calls[@intFromEnum(algorithm)] += 1;
            @memset(output, @intFromEnum(algorithm));
        }
    };
    var fake = Fake{};
    var digests = Digests{
        .hasher = .{ .context = &fake, .digest_fn = Fake.hash, .options = .{ .allow_sha1_identifiers = true, .allow_md5_identifiers = true } },
        .scratch = std.testing.allocator,
        .input = "fixed certificate DER",
    };
    for (std.enums.values(crypto.HashAlgorithm)) |algorithm| {
        const first = try digests.get(algorithm);
        const second = try digests.get(algorithm);
        try std.testing.expectEqual(algorithm.digestLength(), first.len);
        try std.testing.expect(first.ptr == second.ptr);
        try std.testing.expect(std.mem.allEqual(u8, second, @intFromEnum(algorithm)));
        try std.testing.expectEqual(@as(usize, 1), fake.calls[@intFromEnum(algorithm)]);
    }
}

test "Disallowed cache separates algorithm and byte domain even when MD5 outputs collide" {
    const Fake = struct {
        calls: [3]usize = @splat(0),
        failure: bool = false,

        fn hash(context: *anyopaque, _: Allocator, _: crypto.HashAlgorithm, input: []const u8, output: []u8) crypto.ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            const index: usize = if (std.mem.eql(u8, input, "certificate DER")) 0 else if (std.mem.eql(u8, input, "TBS DER")) 1 else if (std.mem.eql(u8, input, "raw key")) 2 else return error.InvalidInput;
            self.calls[index] += 1;
            @memset(output, 0x42);
            if (self.failure) return error.InternalError;
        }
    };
    var fake = Fake{};
    var digests = Digests{
        .hasher = .{ .context = &fake, .digest_fn = Fake.hash, .options = .{ .allow_md5_identifiers = true } },
        .scratch = std.testing.allocator,
        .input = "certificate DER",
        .inputs = .{ .tbs_der = "TBS DER", .public_key_bits = "raw key", .signature_hash = .md5 },
    };
    var outputs: [3][]const u8 = undefined;
    for (std.enums.values(Digests.Domain), &outputs, 0..) |domain, *output, i| {
        output.* = try digests.getDomain(.md5, domain);
        try std.testing.expectEqualSlices(u8, "\x42" ** 16, output.*);
        try std.testing.expect(output.ptr == (try digests.getDomain(.md5, domain)).ptr);
        try std.testing.expectEqual(@as(usize, 1), fake.calls[i]);
        for (outputs[0..i]) |previous| try std.testing.expect(output.ptr != previous.ptr);
    }
    _ = try digests.getDomain(.sha256, .tbs_der);
    try std.testing.expectEqual(@as(usize, 2), fake.calls[1]);
    fake.failure = true;
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, digests.getDomain(.sha384, .tbs_der));
    const domain = @intFromEnum(Digests.Domain.tbs_der);
    const algorithm = @intFromEnum(crypto.HashAlgorithm.sha384);
    try std.testing.expect(!digests.ready[domain][algorithm]);
    try std.testing.expect(std.mem.allEqual(u8, digests.values[domain][algorithm][0..48], 0));
    fake.failure = false;
    _ = try digests.getDomain(.sha384, .tbs_der);
    try std.testing.expectEqual(@as(usize, 4), fake.calls[1]);
}

test "platform metadata ownership and allocation failure" {
    const Test = struct {
        fn run(allocator: Allocator) !void {
            var snapshot = Snapshot.init(allocator, .{});
            defer snapshot.deinit();
            var der = [_]u8{ 1, 2, 3 };
            const index = try snapshot.add(&der, true);
            var rule = Rule{};
            try rule.setHostname("api.example.test");
            try snapshot.setDomain(index, 0, &.{rule});
            der[0] = 99;
            rule.hostname[0] = 'X';
            try std.testing.expectEqual(@as(u8, 1), snapshot.entries.items[0].der[0]);
            try std.testing.expectEqual(@as(u8, 'a'), snapshot.entries.items[0].domains[0].?[0].hostname[0]);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
}

test "platform metadata limits reject before retaining excess input" {
    var snapshot = Snapshot.init(std.testing.allocator, .{ .max_certificates = 1, .max_der_bytes = 3, .max_rules_per_domain = 1 });
    defer snapshot.deinit();
    const index = try snapshot.add("abc", true);
    try std.testing.expectEqual(index, try snapshot.add("abc", false));
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.add("d", false));
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.setDomain(index, 0, &.{ .{}, .{} }));
    try snapshot.setDomain(index, 0, &.{});
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.setDomain(index, 0, &.{}));
}

const server_use: Use = .{
    .role = .server,
    .identity = .{ .dns_name = "api.example.test" },
    .now_seconds = 100,
    .issuer = true,
    .self_issued = true,
};

test "Windows roles denial and conservative cutoff are conjunctive" {
    var windows = Windows{};
    try std.testing.expect(windows.permits(server_use));
    windows.merge(.{ .roles = 1, .disallow_at = 101 });
    try std.testing.expect(windows.permits(server_use));
    var client = server_use;
    client.role = .client;
    try std.testing.expect(!windows.permits(client));
    windows.merge(.{ .disallow_at = 100 });
    try std.testing.expect(!windows.permits(server_use));
    try std.testing.expect(!(Windows{ .roles = 0 }).permits(server_use));
    try std.testing.expect(!(Windows{ .denied_roles = 1 }).permits(server_use));
    try std.testing.expect(!(Windows{ .unsupported = true }).permits(server_use));
}

test "macOS precedence absence empty unspecified and explicit deny" {
    var snapshot = Snapshot.init(std.testing.allocator, .{});
    defer snapshot.deinit();
    const index = try snapshot.add("certificate", true);
    const entry = &snapshot.entries.items[index];
    try std.testing.expectEqual(Decision.anchor, entry.decide(server_use));
    try snapshot.setDomain(index, 2, &.{.{ .result = .deny }});
    try std.testing.expectEqual(Decision.deny, entry.decide(server_use));
    try snapshot.setDomain(index, 1, &.{});
    try std.testing.expectEqual(Decision.self_signed_anchor, entry.decide(server_use));
    try snapshot.setDomain(index, 0, &.{.{ .result = .unspecified }});
    try std.testing.expectEqual(Decision.deny, entry.decide(server_use));
}

test "macOS purpose identity key use alternatives and unsupported constraints" {
    var named = Rule{};
    try named.setHostname("API.example.test.");
    var rules = [_]Rule{named};
    var entry = Entry{ .der = &.{}, .domains = .{ &rules, null, null } };
    try std.testing.expectEqual(Decision.self_signed_anchor, entry.decide(server_use));
    var different = server_use;
    different.identity = .{ .dns_name = "other.example.test" };
    try std.testing.expectEqual(Decision.deny, entry.decide(different));
    rules[0].roles = 2;
    try std.testing.expectEqual(Decision.deny, entry.decide(server_use));
    rules[0].roles = 3;
    rules[0].key_usage = 1;
    try std.testing.expectEqual(Decision.deny, entry.decide(server_use));
    rules[0].key_usage = 8;
    rules[0].unsupported = true;
    try std.testing.expectEqual(Decision.deny, entry.decide(server_use));
    var alternatives = [_]Rule{ .{}, .{ .result = .deny } };
    entry.domains[0] = &alternatives;
    try std.testing.expectEqual(Decision.deny, entry.decide(server_use));
}

test "macOS non-root trust and exact IP constraints" {
    var rule = Rule{ .result = .trust_as_root };
    try rule.setHostname("2001:db8::1");
    var rules = [_]Rule{rule};
    const entry = Entry{ .der = &.{}, .domains = .{ &rules, null, null } };
    var use = server_use;
    use.self_issued = false;
    use.identity = .{ .ip_address = .{ .v6 = .{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };
    try std.testing.expectEqual(Decision.anchor, entry.decide(use));
    use.self_issued = true;
    try std.testing.expectEqual(Decision.deny, entry.decide(use));
    use.self_issued = false;
    use.identity = .{ .ip_address = .{ .v4 = .{ 127, 0, 0, 1 } } };
    try std.testing.expectEqual(Decision.deny, entry.decide(use));
}

test "fingerprint metadata ownership limits and allocation failures" {
    const Test = struct {
        fn run(allocator: Allocator) !void {
            var snapshot = Snapshot.init(allocator, .{ .max_fingerprint_lists = 1, .max_fingerprint_entries = 1 });
            defer snapshot.deinit();
            var entries = [_]FingerprintEntry{try FingerprintEntry.init(.sha1, &@as([20]u8, @splat(1)), .{ .roles = 0 })};
            const list = FingerprintList{ .algorithm = .sha1, .this_update = 50, .next_update = 150, .entries = &entries };
            try snapshot.addFingerprintList(list);
            entries[0].identifier[0] = 99;
            try std.testing.expectEqual(@as(u8, 1), snapshot.fingerprint_lists.items[0].entries[0].identifier[0]);
            try std.testing.expectEqual(@as(usize, 0), snapshot.entries.items.len);
            try std.testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.addFingerprintList(list));
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, FingerprintEntry.init(.sha1, &.{0}, .{}));
    var snapshot = Snapshot.init(std.testing.allocator, .{ .max_fingerprint_entries = 0 });
    defer snapshot.deinit();
    const entry = try FingerprintEntry.init(.sha256, &@as([32]u8, @splat(1)), .{});
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.addFingerprintList(.{
        .algorithm = .sha256,
        .this_update = 100,
        .entries = &.{entry},
    }));
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.addFingerprintList(.{
        .algorithm = .sha256,
        .this_update = 100,
        .next_update = 99,
        .entries = &.{},
    }));
}

test "fingerprint lists intersect duplicate rules cache per call and use request time" {
    const Fake = struct {
        calls: usize = 0,
        fn hash(context: *anyopaque, _: Allocator, _: crypto.HashAlgorithm, _: []const u8, output: []u8) crypto.ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            @memset(output, 1);
        }
    };
    var fake = Fake{};
    const hasher = metadata_digest.MetadataDigest{
        .context = &fake,
        .digest_fn = Fake.hash,
        .options = .{ .allow_sha1_identifiers = true },
    };
    var snapshot = Snapshot.init(std.testing.allocator, .{});
    defer snapshot.deinit();
    const unrestricted = try FingerprintEntry.init(.sha1, &@as([20]u8, @splat(1)), .{});
    const other = try FingerprintEntry.init(.sha1, &@as([20]u8, @splat(0)), .{ .roles = 0 });
    const list = FingerprintList{
        .algorithm = .sha1,
        .this_update = 50,
        .next_update = 150,
        .entries = &.{ unrestricted, other },
    };
    try snapshot.addFingerprintList(list);
    try snapshot.addFingerprintList(list);
    try std.testing.expectEqual(Decision.anchor, try snapshot.check("not an anchor grant", server_use, hasher, std.testing.allocator));
    try std.testing.expectEqual(@as(usize, 1), fake.calls);
    var later = server_use;
    later.now_seconds = 151;
    try std.testing.expectError(error.TlsTrustStoreLoadFailed, snapshot.check("certificate", later, hasher, std.testing.allocator));
    try std.testing.expectEqual(@as(usize, 1), fake.calls);
    try std.testing.expectError(error.TlsInvalidTrustConfiguration, snapshot.check("certificate", server_use, null, std.testing.allocator));
    const denied = try FingerprintEntry.init(.sha1, &@as([20]u8, @splat(1)), .{ .denied_roles = 1 });
    try snapshot.addFingerprintList(.{ .algorithm = .sha1, .this_update = 50, .entries = &.{ unrestricted, denied } });
    try std.testing.expectEqual(Decision.deny, try snapshot.check("certificate", server_use, hasher, std.testing.allocator));
}

test "a secondary SHA256 mismatch is not silently treated as an absent restriction" {
    const Fake = struct {
        fn hash(_: *anyopaque, _: Allocator, _: crypto.HashAlgorithm, _: []const u8, output: []u8) crypto.ProviderError!void {
            @memset(output, 1);
        }
    };
    var context: u8 = 0;
    const hasher = metadata_digest.MetadataDigest{ .context = &context, .digest_fn = Fake.hash, .options = .{ .allow_sha1_identifiers = true } };
    var snapshot = Snapshot.init(std.testing.allocator, .{});
    defer snapshot.deinit();
    var entry = try FingerprintEntry.init(.sha1, &@as([20]u8, @splat(1)), .{});
    entry.sha256 = @splat(2);
    try snapshot.addFingerprintList(.{ .algorithm = .sha1, .this_update = 50, .entries = &.{entry} });
    try std.testing.expectEqual(Decision.deny, try snapshot.check("certificate", server_use, hasher, std.testing.allocator));
}
