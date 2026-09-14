const std = @import("std");
const tls = std.crypto.tls;
const p = @import("provider.zig");
const KeyShare = @import("key_share.zig").KeyShare;

pub const Error = error{ TlsRecordOverflow, TlsIllegalParameter, UnsupportedAlgorithm };
pub const extended_master_secret: tls.ExtensionType = @enumFromInt(23);
pub const signature_schemes = [_]p.SignatureScheme{
    .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256,    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,    .ed25519,
    .rsa_pss_pss_sha256,     .rsa_pss_pss_sha384,
    .rsa_pss_pss_sha512,     .rsa_pkcs1_sha256,
    .rsa_pkcs1_sha384,       .rsa_pkcs1_sha512,
};

const Suite = struct {
    tag: tls.CipherSuite,
    aead: p.AeadAlgorithm,
    hash: p.HashAlgorithm,
    version: tls.ProtocolVersion,
    rsa: ?bool = null,
};

pub const suites = [_]Suite{
    .{ .tag = .AES_128_GCM_SHA256, .aead = .aes_128_gcm, .hash = .sha256, .version = .tls_1_3 },
    .{ .tag = .AES_256_GCM_SHA384, .aead = .aes_256_gcm, .hash = .sha384, .version = .tls_1_3 },
    .{ .tag = .CHACHA20_POLY1305_SHA256, .aead = .chacha20_poly1305, .hash = .sha256, .version = .tls_1_3 },
    .{ .tag = .ECDHE_RSA_WITH_AES_128_GCM_SHA256, .aead = .aes_128_gcm, .hash = .sha256, .version = .tls_1_2, .rsa = true },
    .{ .tag = .ECDHE_RSA_WITH_AES_256_GCM_SHA384, .aead = .aes_256_gcm, .hash = .sha384, .version = .tls_1_2, .rsa = true },
    .{ .tag = .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, .aead = .chacha20_poly1305, .hash = .sha256, .version = .tls_1_2, .rsa = true },
    .{ .tag = .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, .aead = .aes_128_gcm, .hash = .sha256, .version = .tls_1_2, .rsa = false },
    .{ .tag = .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, .aead = .aes_256_gcm, .hash = .sha384, .version = .tls_1_2, .rsa = false },
    .{ .tag = .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, .aead = .chacha20_poly1305, .hash = .sha256, .version = .tls_1_2, .rsa = false },
};

pub fn offered(caps: p.Capabilities, tag: tls.CipherSuite, version: tls.ProtocolVersion) bool {
    for (suites) |suite| {
        if (suite.tag != tag or suite.version != version) continue;
        if (!caps.random or !caps.constant_time_equal or
            !caps.supportsHash(suite.hash) or !caps.supportsHmac(suite.hash) or
            !caps.supportsAead(suite.aead)) return false;
        if (version == .tls_1_3 and !caps.supportsHkdf(suite.hash)) return false;
        if (version == .tls_1_2 and !caps.supportsTls12Prf(suite.hash)) return false;
        for (signature_schemes) |scheme| {
            if (!caps.supportsVerify(scheme)) continue;
            const rsa_pkcs1 = switch (scheme) {
                .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 => true,
                else => false,
            };
            if (version == .tls_1_3 and rsa_pkcs1) continue;
            if (suite.rsa) |rsa| {
                const algorithm = scheme.keyAlgorithm();
                if (rsa and algorithm != .rsa and algorithm != .rsa_pss) continue;
                if (!rsa and algorithm != .ecdsa_p256 and algorithm != .ecdsa_p384 and algorithm != .ed25519) continue;
                // TLS 1.2 applies supported_groups to the certificate curve too.
                if (!rsa and algorithm == .ecdsa_p256 and !caps.supportsKeyAgreement(.secp256r1)) continue;
                if (!rsa and algorithm == .ecdsa_p384 and !caps.supportsKeyAgreement(.secp384r1)) continue;
            }
            return true;
        }
        return false;
    }
    return false;
}

pub fn versionOffered(caps: p.Capabilities, version: tls.ProtocolVersion) bool {
    for (suites) |suite| {
        if (suite.version == version and offered(caps, suite.tag, version)) return true;
    }
    return false;
}

test "client version advertisement follows the selected provider key schedule capabilities" {
    var caps = p.Capabilities.all();
    try std.testing.expect(versionOffered(caps, .tls_1_3));
    for (std.enums.values(p.HashAlgorithm)) |hash| caps.setHkdf(hash, false);
    try std.testing.expect(!versionOffered(caps, .tls_1_3));
    try std.testing.expect(versionOffered(caps, .tls_1_2));
    for (std.enums.values(p.HashAlgorithm)) |hash| caps.setTls12Prf(hash, false);
    try std.testing.expect(!versionOffered(caps, .tls_1_2));
}

const Builder = struct {
    buffer: []u8,
    len: usize = 0,

    fn append(self: *Builder, bytes: []const u8) Error!void {
        if (bytes.len > self.buffer.len - self.len) return error.TlsRecordOverflow;
        @memcpy(self.buffer[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn integer(self: *Builder, value: u16) Error!void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .big);
        try self.append(&bytes);
    }

    fn vector(self: *Builder) Error!usize {
        const offset = self.len;
        try self.integer(0);
        return offset;
    }

    fn finish(self: *Builder, offset: usize) Error!void {
        const len = self.len - offset - 2;
        if (len > std.math.maxInt(u16)) return error.TlsRecordOverflow;
        std.mem.writeInt(u16, self.buffer[offset..][0..2], @intCast(len), .big);
    }

    fn extension(self: *Builder, kind: tls.ExtensionType) Error!usize {
        try self.integer(@intFromEnum(kind));
        return self.vector();
    }
};

pub fn build(out: []u8, caps: p.Capabilities, shares: *const KeyShare, entropy: *const [64]u8, host: []const u8, alpn_extension: []const u8) Error![]const u8 {
    var b: Builder = .{ .buffer = out };
    try b.integer(0x0303);
    try b.append(entropy[0..32]);
    try b.append(&.{32});
    try b.append(entropy[32..64]);
    const cipher_vector = try b.vector();
    var tls13 = false;
    var tls12 = false;
    for (suites) |suite| {
        if (!offered(caps, suite.tag, suite.version)) continue;
        try b.integer(@intFromEnum(suite.tag));
        if (suite.version == .tls_1_3) tls13 = true else tls12 = true;
    }
    if (!tls13 and !tls12) return error.UnsupportedAlgorithm;
    try b.finish(cipher_vector);
    try b.append(&.{ 1, 0 });
    const extensions = try b.vector();
    {
        const ext = try b.extension(.supported_versions);
        try b.append(&.{@as(u8, if (tls13 and tls12) 4 else 2)});
        if (tls13) try b.integer(0x0304);
        if (tls12) try b.integer(0x0303);
        try b.finish(ext);
    }
    {
        const ext = try b.extension(.signature_algorithms);
        const list = try b.vector();
        for (signature_schemes) |scheme| {
            if (caps.supportsVerify(scheme)) try b.integer(@intFromEnum(scheme));
        }
        try b.finish(list);
        try b.finish(ext);
    }
    {
        const ext = try b.extension(.supported_groups);
        const list = try b.vector();
        for (KeyShare.algorithms) |algorithm| {
            if (shares.publicKey(@enumFromInt(@intFromEnum(algorithm))) != null)
                try b.integer(@intFromEnum(algorithm));
        }
        if (b.len == list + 2) return error.UnsupportedAlgorithm;
        try b.finish(list);
        try b.finish(ext);
    }
    if (tls13) {
        const ext = try b.extension(.key_share);
        const list = try b.vector();
        for (KeyShare.algorithms) |algorithm| {
            const public_key = shares.publicKey(@enumFromInt(@intFromEnum(algorithm))) orelse continue;
            try b.integer(@intFromEnum(algorithm));
            try b.integer(@intCast(public_key.len));
            try b.append(public_key);
        }
        try b.finish(list);
        try b.finish(ext);
    }
    if (tls12) {
        const ext = try b.extension(extended_master_secret);
        try b.finish(ext);
    }
    if (host.len > 0) {
        if (host.len > 253) return error.TlsIllegalParameter;
        for (host) |byte| if (byte < 0x21 or byte > 0x7e) return error.TlsIllegalParameter;
        const is_ip = std.mem.indexOfScalar(u8, host, ':') != null or
            std.mem.indexOfNone(u8, host, "0123456789.") == null;
        if (!is_ip) {
            const ext = try b.extension(.server_name);
            const list = try b.vector();
            try b.append(&.{0});
            try b.integer(@intCast(host.len));
            try b.append(host);
            try b.finish(list);
            try b.finish(ext);
        }
    }
    try b.append(alpn_extension);
    try b.finish(extensions);
    return b.buffer[0..b.len];
}
