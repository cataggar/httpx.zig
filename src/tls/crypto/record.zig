const std = @import("std");
const p = @import("provider.zig");
const state = @import("tls_state.zig");
const tls = std.crypto.tls;

pub const Error = p.ProviderError || error{ TlsUnsupportedCipherSuite, TlsDecodeError, TlsDecryptError, TlsRecordOverflow };
const Profile = struct { aead: p.AeadAlgorithm, hash: p.HashAlgorithm, explicit_iv_length: usize };

fn profile(version: tls.ProtocolVersion, suite: tls.CipherSuite) Error!Profile {
    return switch (version) {
        .tls_1_3 => switch (suite) {
            .AES_128_GCM_SHA256 => .{ .aead = .aes_128_gcm, .hash = .sha256, .explicit_iv_length = 0 },
            .AES_256_GCM_SHA384 => .{ .aead = .aes_256_gcm, .hash = .sha384, .explicit_iv_length = 0 },
            .CHACHA20_POLY1305_SHA256 => .{ .aead = .chacha20_poly1305, .hash = .sha256, .explicit_iv_length = 0 },
            else => error.TlsUnsupportedCipherSuite,
        },
        .tls_1_2 => switch (suite) {
            .ECDHE_RSA_WITH_AES_128_GCM_SHA256, .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => .{ .aead = .aes_128_gcm, .hash = .sha256, .explicit_iv_length = 8 },
            .ECDHE_RSA_WITH_AES_256_GCM_SHA384, .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => .{ .aead = .aes_256_gcm, .hash = .sha384, .explicit_iv_length = 8 },
            .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => .{ .aead = .chacha20_poly1305, .hash = .sha256, .explicit_iv_length = 0 },
            else => error.TlsUnsupportedCipherSuite,
        },
        else => error.TlsUnsupportedCipherSuite,
    };
}

fn xorNonce(iv: [12]u8, seq: u64) [12]u8 {
    var nonce = iv;
    var sequence: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequence, seq, .big);
    for (nonce[4..], sequence) |*byte, mask| byte.* ^= mask;
    return nonce;
}

fn associatedData(header: *const [5]u8, seq: u64, plaintext_len: usize) [13]u8 {
    var aad: [13]u8 = undefined;
    std.mem.writeInt(u64, aad[0..8], seq, .big);
    @memcpy(aad[8..11], header[0..3]);
    std.mem.writeInt(u16, aad[11..13], @intCast(plaintext_len), .big);
    return aad;
}

pub fn seal(provider: p.CryptoProvider, version: tls.ProtocolVersion, suite: tls.CipherSuite, out: []u8, plaintext: []const u8, header: *const [5]u8, key: *const [32]u8, iv: *const [12]u8, seq: u64) Error![]u8 {
    const algorithm = try profile(version, suite);
    const maximum: usize = if (version == .tls_1_3) 16385 else 16384;
    if (plaintext.len > maximum) return error.TlsRecordOverflow;
    const length = algorithm.explicit_iv_length + plaintext.len + 16;
    if (out.len < length) return error.OutputTooSmall;
    var nonce = xorNonce(iv.*, seq);
    if (algorithm.explicit_iv_length != 0) {
        std.mem.writeInt(u64, out[0..8], seq, .big);
        @memcpy(nonce[0..4], iv[0..4]);
        @memcpy(nonce[4..12], out[0..8]);
    }
    var aad12: [13]u8 = undefined;
    const aad = if (version == .tls_1_2) blk: {
        aad12 = associatedData(header, seq, plaintext.len);
        break :blk &aad12;
    } else @as([]const u8, header);
    const ciphertext = out[algorithm.explicit_iv_length..][0..plaintext.len];
    const tag = out[length - 16 ..][0..16];
    try provider.aeadSeal(algorithm.aead, key[0..algorithm.aead.keyLength()], &nonce, &.{aad}, plaintext, ciphertext, tag);
    return out[0..length];
}

pub fn open(provider: p.CryptoProvider, version: tls.ProtocolVersion, suite: tls.CipherSuite, body: []u8, header: *const [5]u8, key: *const [32]u8, iv: *const [12]u8, seq: u64) Error![]u8 {
    const algorithm = try profile(version, suite);
    if (body.len < algorithm.explicit_iv_length + 16) return error.TlsDecodeError;
    const ciphertext = body[algorithm.explicit_iv_length .. body.len - 16];
    if (ciphertext.len > (if (version == .tls_1_3) @as(usize, 16624) else 16384))
        return error.TlsRecordOverflow;
    var nonce = xorNonce(iv.*, seq);
    if (algorithm.explicit_iv_length != 0) {
        @memcpy(nonce[0..4], iv[0..4]);
        @memcpy(nonce[4..12], body[0..8]);
    }
    var aad12: [13]u8 = undefined;
    const aad = if (version == .tls_1_2) blk: {
        aad12 = associatedData(header, seq, ciphertext.len);
        break :blk &aad12;
    } else @as([]const u8, header);
    const tag = body[body.len - 16 ..][0..16].*;
    provider.aeadOpen(algorithm.aead, key[0..algorithm.aead.keyLength()], &nonce, &.{aad}, ciphertext, &tag, ciphertext) catch |err|
        return if (err == error.AuthenticationFailed) error.TlsDecryptError else err;
    return ciphertext;
}

pub fn updateTrafficKeys(provider: p.CryptoProvider, suite: tls.CipherSuite, secret: *[48]u8, key: *[32]u8, iv: *[12]u8) Error!void {
    const algorithm = try profile(.tls_1_3, suite);
    var next_key: [32]u8 = @splat(0);
    defer p.secureWipe(&next_key);
    switch (algorithm.hash) {
        inline .sha256, .sha384 => |hash| {
            const K = state.HkdfType(hash);
            var next_secret = try state.hkdfExpandLabel(provider, K, secret[0..K.prk_length].*, "traffic upd", "", K.prk_length);
            defer p.secureWipe(&next_secret);
            if (algorithm.aead == .aes_128_gcm) {
                var derived = try state.hkdfExpandLabel(provider, K, next_secret, "key", "", 16);
                defer p.secureWipe(&derived);
                @memcpy(next_key[0..16], &derived);
            } else {
                next_key = try state.hkdfExpandLabel(provider, K, next_secret, "key", "", 32);
            }
            const next_iv = try state.hkdfExpandLabel(provider, K, next_secret, "iv", "", 12);
            p.secureWipe(secret);
            @memcpy(secret[0..K.prk_length], &next_secret);
            key.* = next_key;
            iv.* = next_iv;
        },
        else => unreachable,
    }
}
