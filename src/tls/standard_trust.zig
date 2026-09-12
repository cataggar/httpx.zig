//! Immutable certificate path policy. Certificate signatures use
//! only the request's selected verifier; system roots are discovery input, not
//! permission to bypass path policy. See docs/api/standard-trust.md.
const std = @import("std");
const builtin = @import("builtin");
const trust = @import("trust.zig");
const x509 = @import("x509_policy.zig");
const platform = @import("platform_trust.zig");
const Error = trust.TrustError;
const Allocator = std.mem.Allocator;

pub const Options = struct {
    source: trust.TrustSource = .system,
    max_trust_anchors: usize = 4096,
    max_certificate_der_bytes: usize = 256 * 1024,
    max_trust_store_der_bytes: usize = 16 * 1024 * 1024,
    max_pem_bytes: usize = 32 * 1024 * 1024,
    /// Peak Zig allocator payload used by system discovery. OS-owned API
    /// allocations are not controlled by a Zig allocator.
    max_system_load_bytes: usize = 64 * 1024 * 1024,
    /// Includes distrust-only certificates, not just anchor candidates.
    max_system_certificates: usize = 8192,
    /// Root-discovery snapshot time, not the per-handshake verification time.
    load_time_seconds: ?i64 = null,

    fn validate(self: Options) Error!void {
        if (self.max_trust_anchors == 0 or self.max_certificate_der_bytes == 0 or
            self.max_trust_store_der_bytes < self.max_certificate_der_bytes or
            self.max_pem_bytes == 0 or self.max_system_load_bytes == 0 or self.max_system_certificates == 0)
            return error.TlsInvalidTrustConfiguration;
    }
};

const Anchor = struct {
    bytes: []u8,
    certificate: x509.Certificate,
};

/// Owns copied trust anchors, but never owns a `.source.provider` handle.
/// Keep this owner at a stable address after calling `provider`. No mutable
/// state or provider allocator is used by verification; concurrent calls need
/// independent/thread-safe request scratch allocators and signature verifiers.
/// The provider and all active calls must end before `deinit`.
pub const TrustContext = struct {
    allocator: Allocator,
    anchors: []Anchor,
    borrowed: ?trust.TrustProvider = null,
    platform_snapshot: ?platform.Snapshot = null,
    /// System certificates outside this strict profile are never trusted.
    skipped_system_anchors: usize = 0,

    pub fn init(allocator: Allocator, io: std.Io, options: Options) Error!TrustContext {
        try options.validate();
        if (options.source == .provider) return .{
            .allocator = allocator,
            .anchors = &.{},
            .borrowed = options.source.provider,
        };
        var builder = Builder{ .allocator = allocator, .options = options };
        defer builder.deinit();
        switch (options.source) {
            .system => try builder.system(io),
            .system_plus_custom => |source| {
                try builder.system(io);
                try builder.custom(io, source);
            },
            .custom_only => |source| try builder.custom(io, source),
            .provider => unreachable,
        }
        if (builder.anchors.items.len == 0) return error.TlsNoTrustAnchors;
        std.mem.sort(Anchor, builder.anchors.items, {}, struct {
            fn lessThan(_: void, a: Anchor, b: Anchor) bool {
                return std.mem.order(u8, a.certificate.subject, b.certificate.subject) == .lt;
            }
        }.lessThan);
        const anchors = try builder.anchors.toOwnedSlice(allocator);
        const snapshot = builder.platform_snapshot;
        builder.platform_snapshot = null;
        return .{
            .allocator = allocator,
            .anchors = anchors,
            .skipped_system_anchors = builder.skipped,
            .platform_snapshot = snapshot,
        };
    }

    pub fn provider(self: *TrustContext) trust.TrustProvider {
        return self.borrowed orelse .{ .context = self, .vtable = &.{ .verify_peer = verifyPeer } };
    }

    pub fn anchorCount(self: *const TrustContext) usize {
        return self.anchors.len;
    }

    pub fn deinit(self: *TrustContext) void {
        for (self.anchors) |anchor| self.allocator.free(anchor.bytes);
        self.allocator.free(self.anchors);
        if (self.platform_snapshot) |*snapshot| snapshot.deinit();
        self.* = undefined;
    }

    fn verifyPeer(context: *anyopaque, request: trust.VerifyPeerRequest) Error!void {
        const self: *const TrustContext = @ptrCast(@alignCast(context));
        try request.validate();
        if (request.role == .server and request.expected_identity == null)
            return error.TlsInvalidTrustConfiguration;
        const allocator = request.scratch_allocator;
        const peers = try allocator.alloc(x509.Certificate, request.chain_der.len);
        defer allocator.free(peers);
        for (request.chain_der, 0..) |bytes, i| {
            for (request.chain_der[0..i]) |prior| {
                if (std.mem.eql(u8, prior, bytes)) return error.TlsMalformedCertificateChain;
            }
            peers[i] = try x509.parse(bytes);
        }
        try peers[0].checkPolicy(request.now_seconds, request.role, false, 0);
        if (request.expected_identity) |identity| try peers[0].checkIdentity(identity);
        _ = try self.checkMetadata(peers[0], request, false, false);
        if (request.limits.max_path_depth < 2) return error.TlsCertificatePathTooDeep;

        const visited = try allocator.alloc(bool, peers.len);
        defer allocator.free(visited);
        @memset(visited, false);
        visited[0] = true;
        const frames = try allocator.alloc(Frame, @min(peers.len, request.limits.max_path_depth - 1));
        defer allocator.free(frames);
        frames[0] = self.frame(peers[0], 0, 0);
        var depth: usize = 1;
        var attempts: usize = 0;
        var depth_limited = false;
        var failure: Error = error.TlsUnknownCa;
        while (depth != 0) {
            const current = &frames[depth - 1];
            const child = peers[current.peer_index];
            const below = current.ca_below + @intFromBool(current.peer_index != 0 and !child.selfIssued());
            var candidate: ?x509.Certificate = null;
            var candidate_peer: ?usize = null;
            while (current.next_peer < peers.len) {
                const index = current.next_peer;
                current.next_peer += 1;
                if (visited[index] or !std.mem.eql(u8, peers[index].subject, child.issuer)) continue;
                candidate = peers[index];
                candidate_peer = index;
                break;
            }
            if (candidate == null and current.next_anchor < current.anchor_end) {
                candidate = self.anchors[current.next_anchor].certificate;
                current.next_anchor += 1;
            }
            const issuer = candidate orelse {
                visited[current.peer_index] = false;
                depth -= 1;
                continue;
            };
            if (attempts == request.limits.max_candidate_attempts)
                return error.TlsCertificatePathSearchLimitExceeded;
            attempts += 1;
            const is_anchor = candidate_peer == null;
            if (depth + 1 > request.limits.max_path_depth or (!is_anchor and depth == frames.len)) {
                depth_limited = true;
                continue;
            }
            issuer.checkPolicy(request.now_seconds, request.role, true, below) catch |err| {
                failure = err;
                continue;
            };
            const self_signature_required = self.checkMetadata(issuer, request, true, is_anchor) catch |err| {
                failure = err;
                continue;
            };
            if (child.authority_key_id) |authority_id| {
                if (issuer.subject_key_id) |subject_id| {
                    if (!std.mem.eql(u8, authority_id, subject_id)) {
                        failure = error.TlsCertificateConstraintViolation;
                        continue;
                    }
                }
            }
            verifyEdge(child, issuer, request.signature_verifier) catch |err| {
                if (err == error.OutOfMemory) return err;
                failure = err;
                continue;
            };
            if (self_signature_required) {
                verifyEdge(issuer, issuer, request.signature_verifier) catch |err| {
                    if (err == error.OutOfMemory) return err;
                    failure = err;
                    continue;
                };
            }
            // An anchor's provenance is its configured/system trust source.
            // Its self-signature is not a trust proof; all child edges are.
            if (is_anchor) return;
            const index = candidate_peer.?;
            visited[index] = true;
            frames[depth] = self.frame(issuer, index, below);
            depth += 1;
        }
        return if (depth_limited) error.TlsCertificatePathTooDeep else failure;
    }

    fn checkMetadata(self: *const TrustContext, certificate: x509.Certificate, request: trust.VerifyPeerRequest, issuer: bool, anchor: bool) Error!bool {
        const snapshot = self.platform_snapshot orelse return false;
        return switch (snapshot.decide(certificate.der_bytes, .{
            .role = request.role,
            .identity = request.expected_identity,
            .now_seconds = request.now_seconds,
            .issuer = issuer,
            .self_issued = certificate.selfIssued(),
        })) {
            .deny => error.TlsCertificateConstraintViolation,
            .chain_only => if (anchor) error.TlsCertificateConstraintViolation else false,
            .anchor => false,
            .self_signed_anchor => anchor,
        };
    }

    fn frame(self: *const TrustContext, child: x509.Certificate, index: usize, ca_below: usize) Frame {
        var low: usize = 0;
        var high = self.anchors.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (std.mem.order(u8, self.anchors[mid].certificate.subject, child.issuer) == .lt) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        var end = low;
        while (end < self.anchors.len and std.mem.eql(u8, self.anchors[end].certificate.subject, child.issuer))
            end += 1;
        return .{ .peer_index = index, .next_anchor = low, .anchor_end = end, .ca_below = ca_below };
    }
};

const Frame = struct {
    peer_index: usize,
    next_peer: usize = 1,
    next_anchor: usize,
    anchor_end: usize,
    ca_below: usize,
};

fn verifyEdge(child: x509.Certificate, issuer: x509.Certificate, verifier: trust.CertificateSignatureVerifier) Error!void {
    if (!x509.strongSignature(child.algorithm)) return error.TlsUnsupportedCertificateSignatureAlgorithm;
    verifier.verify(.{
        .algorithm = child.algorithm,
        .issuer_spki_der = issuer.spki,
        .tbs_certificate_der = child.tbs,
        .signature = child.signature_bytes,
    }) catch |err| return switch (err) {
        error.UnsupportedAlgorithm => error.TlsUnsupportedCertificateSignatureAlgorithm,
        error.MalformedAlgorithmIdentifier, error.MalformedSubjectPublicKeyInfo => error.TlsMalformedCertificate,
        error.InvalidSignature => error.TlsCertificateSignatureInvalid,
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// Root-file discovery or a metadata-aware, read-only OS snapshot is available.
/// Unsupported OS metadata fails closed; this is not OS chain-engine parity.
pub fn supportsSystemRoots() bool {
    return switch (builtin.os.tag) {
        .linux, .freebsd, .openbsd, .netbsd, .dragonfly, .illumos, .haiku, .serenity, .windows => true,
        .macos => true,
        else => false,
    };
}

const Builder = struct {
    allocator: Allocator,
    options: Options,
    anchors: std.ArrayList(Anchor) = .empty,
    der_bytes: usize = 0,
    skipped: usize = 0,
    platform_snapshot: ?platform.Snapshot = null,

    fn deinit(self: *Builder) void {
        for (self.anchors.items) |anchor| self.allocator.free(anchor.bytes);
        self.anchors.deinit(self.allocator);
        if (self.platform_snapshot) |*snapshot| snapshot.deinit();
    }

    fn add(self: *Builder, bytes: []const u8) Error!void {
        if (bytes.len > self.options.max_certificate_der_bytes) return error.TlsCertificateTooLarge;
        for (self.anchors.items) |anchor| {
            if (std.mem.eql(u8, anchor.bytes, bytes)) return;
        }
        if (self.anchors.items.len == self.options.max_trust_anchors or
            bytes.len > self.options.max_trust_store_der_bytes - self.der_bytes)
            return error.TlsTrustStoreLoadFailed;
        const parsed = try x509.parse(bytes);
        if (!parsed.is_ca or parsed.weak_key) return error.TlsCertificateUsageInvalid;
        if (parsed.unhandled_critical or parsed.unsupported_constraints)
            return error.TlsCertificateConstraintViolation;
        const owned = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(owned);
        try self.anchors.append(self.allocator, .{ .bytes = owned, .certificate = try x509.parse(owned) });
        self.der_bytes += bytes.len;
    }

    fn custom(self: *Builder, io: std.Io, source: trust.CaBundleSource) Error!void {
        switch (source) {
            .der_certificates => |certificates| {
                if (certificates.len > self.options.max_trust_anchors) return error.TlsTrustStoreLoadFailed;
                for (certificates) |bytes| try self.add(bytes);
            },
            .pem_bytes => |bytes| try self.pem(bytes),
            .pem_file_path => |path| {
                if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null) return error.TlsInvalidTrustConfiguration;
                const bytes = std.Io.Dir.cwd().readFileAlloc(
                    io,
                    path,
                    self.allocator,
                    .limited(self.options.max_pem_bytes),
                ) catch |err| return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.TlsTrustStoreLoadFailed,
                };
                defer self.allocator.free(bytes);
                try self.pem(bytes);
            },
        }
    }

    fn pem(self: *Builder, bytes: []const u8) Error!void {
        if (bytes.len > self.options.max_pem_bytes) return error.TlsTrustStoreLoadFailed;
        const begin = "-----BEGIN CERTIFICATE-----";
        const end = "-----END CERTIFICATE-----";
        const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
        var rest = bytes;
        while (true) {
            rest = std.mem.trim(u8, rest, " \t\r\n");
            if (rest.len == 0) return;
            if (!std.mem.startsWith(u8, rest, begin)) return error.TlsTrustStoreLoadFailed;
            rest = rest[begin.len..];
            const end_index = std.mem.indexOf(u8, rest, end) orelse return error.TlsTrustStoreLoadFailed;
            const encoded = rest[0..end_index];
            const buffer = try self.allocator.alloc(u8, @min(
                self.options.max_certificate_der_bytes,
                decoder.calcSizeUpperBound(encoded.len),
            ));
            defer self.allocator.free(buffer);
            const length = decoder.decode(buffer, encoded) catch |err| return switch (err) {
                error.NoSpaceLeft => error.TlsCertificateTooLarge,
                else => error.TlsTrustStoreLoadFailed,
            };
            try self.add(buffer[0..length]);
            rest = rest[end_index + end.len ..];
        }
    }

    fn system(self: *Builder, io: std.Io) Error!void {
        if (comptime !supportsSystemRoots()) return error.TlsTrustStoreLoadFailed;
        var limited = LoadAllocator{ .child = self.allocator, .limit = self.options.max_system_load_bytes };
        const allocator = limited.allocator();
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .macos) {
            const loader = if (builtin.os.tag == .windows) @import("platform_trust_windows.zig") else @import("platform_trust_macos.zig");
            var snapshot = loader.load(allocator, .{
                .max_certificates = self.options.max_system_certificates,
                .max_certificate_bytes = self.options.max_certificate_der_bytes,
                .max_der_bytes = self.options.max_trust_store_der_bytes,
            }) catch |err| return if (err == error.OutOfMemory and limited.limit_hit) error.TlsTrustStoreLoadFailed else err;
            // The limiting allocator lives only during construction. Ownership
            // transfers to its underlying allocator, never to its stack address.
            snapshot.allocator = self.allocator;
            self.platform_snapshot = snapshot;
            for (snapshot.entries.items) |entry| {
                if (!entry.anchor_candidate) continue;
                self.add(entry.der) catch |err| switch (err) {
                    error.TlsMalformedCertificate, error.TlsCertificateUsageInvalid, error.TlsCertificateConstraintViolation => self.skipped += 1,
                    else => return err,
                };
            }
            return;
        }
        var bundle: std.crypto.Certificate.Bundle = .empty;
        defer bundle.deinit(allocator);
        const now: std.Io.Timestamp = if (self.options.load_time_seconds) |seconds|
            .{ .nanoseconds = @as(i96, seconds) * std.time.ns_per_s }
        else
            .now(io, .real);
        bundle.rescan(allocator, io, now) catch |err| return switch (err) {
            error.OutOfMemory => if (limited.limit_hit) error.TlsTrustStoreLoadFailed else error.OutOfMemory,
            else => error.TlsTrustStoreLoadFailed,
        };
        var certificates = x509.Reader.init(bundle.bytes.items);
        while (certificates.peek() != null) {
            const certificate = try certificates.take(0x30);
            self.add(certificate.encoded) catch |err| switch (err) {
                error.TlsMalformedCertificate, error.TlsCertificateUsageInvalid, error.TlsCertificateConstraintViolation => self.skipped += 1,
                else => return err,
            };
        }
    }
};

/// Bounds stdlib discovery's peak allocation, including decoded and input
/// buffers. Kept private and used only during single-threaded initialization.
const LoadAllocator = struct {
    child: Allocator,
    limit: usize,
    held: usize = 0,
    limit_hit: bool = false,

    fn allocator(self: *LoadAllocator) Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn room(self: *LoadAllocator, old: usize, new: usize) bool {
        if (new > old and new - old > self.limit - self.held) {
            self.limit_hit = true;
            return false;
        }
        return true;
    }

    fn alloc(context: *anyopaque, length: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
        const self: *LoadAllocator = @ptrCast(@alignCast(context));
        if (!self.room(0, length)) return null;
        const result = self.child.rawAlloc(length, alignment, address) orelse return null;
        self.held += length;
        return result;
    }

    fn resize(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, length: usize, address: usize) bool {
        const self: *LoadAllocator = @ptrCast(@alignCast(context));
        if (!self.room(bytes.len, length) or !self.child.rawResize(bytes, alignment, length, address)) return false;
        self.held = self.held - bytes.len + length;
        return true;
    }

    fn remap(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, length: usize, address: usize) ?[*]u8 {
        const self: *LoadAllocator = @ptrCast(@alignCast(context));
        if (!self.room(bytes.len, length)) return null;
        const result = self.child.rawRemap(bytes, alignment, length, address) orelse return null;
        self.held = self.held - bytes.len + length;
        return result;
    }

    fn free(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, address: usize) void {
        const self: *LoadAllocator = @ptrCast(@alignCast(context));
        self.child.rawFree(bytes, alignment, address);
        self.held -= bytes.len;
    }
};

test "trust initialization rejects empty and invalid configurations" {
    try std.testing.expectError(error.TlsNoTrustAnchors, TrustContext.init(std.testing.allocator, std.testing.io, .{
        .source = .{ .custom_only = .{ .der_certificates = &.{} } },
    }));
    try std.testing.expectError(error.TlsInvalidTrustConfiguration, TrustContext.init(std.testing.allocator, std.testing.io, .{
        .max_trust_anchors = 0,
    }));
}
