//! Fallible standalone TLS helpers. Selecting a provider is mandatory.
const std = @import("std");
const p = @import("provider.zig");
const state = @import("tls_state.zig");
const record = @import("record.zig");

pub fn encryptTLS13(provider: p.CryptoProvider, comptime algorithm: p.AeadAlgorithm, out: []u8, plaintext: []const u8, header: *const [5]u8, nonce: *const [12]u8, key: *const [algorithm.keyLength()]u8) ![]u8 {
    if (plaintext.len > 16624) return error.TlsRecordOverflow;
    if (out.len < plaintext.len + 16) return error.OutputTooSmall;
    try provider.aeadSeal(algorithm, key, nonce, &.{header}, plaintext, out[0..plaintext.len], out[plaintext.len..][0..16]);
    return out[0 .. plaintext.len + 16];
}

pub fn decryptTLS13(provider: p.CryptoProvider, comptime algorithm: p.AeadAlgorithm, ciphertext: []u8, header: *const [5]u8, nonce: *const [12]u8, key: *const [algorithm.keyLength()]u8) ![]u8 {
    if (ciphertext.len < 16) return error.TlsDecryptError;
    if (ciphertext.len > 16640) return error.TlsRecordOverflow;
    const plain = ciphertext[0 .. ciphertext.len - 16];
    const tag = ciphertext[ciphertext.len - 16 ..][0..16].*;
    provider.aeadOpen(algorithm, key, nonce, &.{header}, plain, &tag, plain) catch |err|
        return if (err == error.AuthenticationFailed) error.TlsDecryptError else err;
    return plain;
}

fn tls12Suite(comptime algorithm: p.AeadAlgorithm) std.crypto.tls.CipherSuite {
    return switch (algorithm) {
        .aes_128_gcm => .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .aes_256_gcm => .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .chacha20_poly1305 => .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
}

pub fn encryptTLS12(provider: p.CryptoProvider, comptime algorithm: p.AeadAlgorithm, out: []u8, plaintext: []const u8, header: *const [5]u8, seq: u64, iv: *const [12]u8, key: *const [algorithm.keyLength()]u8) ![]u8 {
    var padded_key: [32]u8 = @splat(0);
    defer p.secureWipe(&padded_key);
    @memcpy(padded_key[0..key.len], key);
    return record.seal(provider, .tls_1_2, tls12Suite(algorithm), out, plaintext, header, &padded_key, iv, seq);
}

pub fn decryptTLS12(provider: p.CryptoProvider, comptime algorithm: p.AeadAlgorithm, ciphertext: []u8, header: *const [5]u8, seq: u64, iv: *const [12]u8, key: *const [algorithm.keyLength()]u8) ![]u8 {
    var padded_key: [32]u8 = @splat(0);
    defer p.secureWipe(&padded_key);
    @memcpy(padded_key[0..key.len], key);
    return record.open(provider, .tls_1_2, tls12Suite(algorithm), ciphertext, header, &padded_key, iv, seq);
}

pub fn hmacSha256Expand(provider: p.CryptoProvider, secret: []const u8, label: []const u8, seed: []const u8, out: []u8) p.ProviderError!void {
    return provider.tls12Prf(.sha256, secret, label, &.{seed}, out);
}

pub fn hmacSha384Expand(provider: p.CryptoProvider, secret: []const u8, label: []const u8, seed: []const u8, out: []u8) p.ProviderError!void {
    return provider.tls12Prf(.sha384, secret, label, &.{seed}, out);
}

pub fn deriveMasterSecret256(provider: p.CryptoProvider, shared_secret: []const u8, client_random: *const [32]u8, server_random: *const [32]u8) p.ProviderError![48]u8 {
    var out: [48]u8 = undefined;
    try provider.tls12Prf(.sha256, shared_secret, "master secret", &.{ client_random, server_random }, &out);
    return out;
}

pub fn deriveMasterSecret384(provider: p.CryptoProvider, shared_secret: []const u8, client_random: *const [32]u8, server_random: *const [32]u8) p.ProviderError![48]u8 {
    var out: [48]u8 = undefined;
    try provider.tls12Prf(.sha384, shared_secret, "master secret", &.{ client_random, server_random }, &out);
    return out;
}

pub fn deriveKeyBlock256(provider: p.CryptoProvider, master_secret: *const [48]u8, server_random: *const [32]u8, client_random: *const [32]u8, comptime len: usize) p.ProviderError![len]u8 {
    var out: [len]u8 = undefined;
    try provider.tls12Prf(.sha256, master_secret, "key expansion", &.{ server_random, client_random }, &out);
    return out;
}

pub fn deriveKeyBlock384(provider: p.CryptoProvider, master_secret: *const [48]u8, server_random: *const [32]u8, client_random: *const [32]u8, comptime len: usize) p.ProviderError![len]u8 {
    var out: [len]u8 = undefined;
    try provider.tls12Prf(.sha384, master_secret, "key expansion", &.{ server_random, client_random }, &out);
    return out;
}

pub fn hkdfExtract(provider: p.CryptoProvider, ikm: []const u8, salt: []const u8, comptime hash_len: usize) p.ProviderError![hash_len]u8 {
    const hash: p.HashAlgorithm = switch (hash_len) {
        32 => .sha256,
        48 => .sha384,
        else => return error.InvalidInput,
    };
    var result: [hash_len]u8 = undefined;
    try provider.hkdfExtract(hash, salt, &.{ikm}, &result);
    return result;
}

pub fn hkdfExpandLabel(provider: p.CryptoProvider, prk: []const u8, label: []const u8, context: []const u8, comptime out_len: usize) p.ProviderError![out_len]u8 {
    return switch (prk.len) {
        32 => state.hkdfExpandLabel(provider, state.HkdfType(.sha256), prk[0..32].*, label, context, out_len),
        48 => state.hkdfExpandLabel(provider, state.HkdfType(.sha384), prk[0..48].*, label, context, out_len),
        else => error.InvalidInput,
    };
}

pub fn deriveHandshakeSecret13(provider: p.CryptoProvider, allocator: std.mem.Allocator, shared_secret: []const u8, comptime hash_len: usize) p.ProviderError![hash_len]u8 {
    const hash: p.HashAlgorithm = switch (hash_len) {
        32 => .sha256,
        48 => .sha384,
        else => return error.InvalidInput,
    };
    const zero: [hash_len]u8 = @splat(0);
    var early = try hkdfExtract(provider, &zero, &zero, hash_len);
    defer p.secureWipe(&early);
    const empty_hash = try state.emptyHash(provider, allocator, state.HashType(hash));
    var derived = try hkdfExpandLabel(provider, &early, "derived", &empty_hash, hash_len);
    defer p.secureWipe(&derived);
    return hkdfExtract(provider, shared_secret, &derived, hash_len);
}

pub const TrafficKeys = struct { key16: [16]u8, key32: [32]u8, iv: [12]u8 };

pub fn deriveTrafficKeys13(provider: p.CryptoProvider, secret: []const u8) p.ProviderError!TrafficKeys {
    var keys: TrafficKeys = undefined;
    errdefer p.secureWipeValue(&keys);
    keys.key16 = try hkdfExpandLabel(provider, secret, "key", "", 16);
    keys.key32 = try hkdfExpandLabel(provider, secret, "key", "", 32);
    keys.iv = try hkdfExpandLabel(provider, secret, "iv", "", 12);
    return keys;
}

test "standalone TLS derivations retain seed order and support both hash sizes" {
    const testing = std.testing;
    var standard = @import("standard.zig").StandardProvider.init(testing.io, testing.allocator);
    const provider = standard.provider();
    const client: [32]u8 = @splat(1);
    const server: [32]u8 = @splat(2);
    inline for (.{ 32, 48 }) |size| {
        const master = if (size == 32)
            try deriveMasterSecret256(provider, "shared", &client, &server)
        else
            try deriveMasterSecret384(provider, "shared", &client, &server);
        var expected: [48]u8 = undefined;
        if (size == 32)
            try hmacSha256Expand(provider, "shared", "master secret", &(client ++ server), &expected)
        else
            try hmacSha384Expand(provider, "shared", "master secret", &(client ++ server), &expected);
        try testing.expectEqualSlices(u8, &expected, &master);
        const block = if (size == 32)
            try deriveKeyBlock256(provider, &master, &server, &client, 48)
        else
            try deriveKeyBlock384(provider, &master, &server, &client, 48);
        if (size == 32)
            try hmacSha256Expand(provider, &master, "key expansion", &(server ++ client), &expected)
        else
            try hmacSha384Expand(provider, &master, "key expansion", &(server ++ client), &expected);
        try testing.expectEqualSlices(u8, &expected, &block);
        const secret = try deriveHandshakeSecret13(provider, testing.allocator, "shared", size);
        const keys = try deriveTrafficKeys13(provider, &secret);
        try testing.expect(!std.mem.eql(u8, &keys.key16, keys.key32[0..16]));
        try testing.expectError(error.InvalidInput, hkdfExpandLabel(provider, &secret, "key", &(@as([256]u8, @splat(0))), 16));
    }
    try testing.expectError(error.InvalidInput, hkdfExtract(provider, "", "", 20));
    try testing.expectError(error.InvalidInput, hkdfExpandLabel(provider, "wrong-size", "key", "", 16));
}

test "standalone TLS AEAD helpers dispatch all suites with bounded output" {
    const testing = std.testing;
    var standard = @import("standard.zig").StandardProvider.init(testing.io, testing.allocator);
    const provider = standard.provider();
    inline for (std.enums.values(p.AeadAlgorithm)) |algorithm| {
        const key: [algorithm.keyLength()]u8 = @splat(7);
        const iv: [12]u8 = @splat(3);
        const header: [5]u8 = .{ 23, 3, 3, 0, 23 };
        var out: [64]u8 = undefined;
        const encrypted12 = try encryptTLS12(provider, algorithm, &out, "message", &header, 42, &iv, &key);
        const plain12 = try decryptTLS12(provider, algorithm, encrypted12, &header, 42, &iv, &key);
        try testing.expectEqualStrings("message", plain12);
        const encrypted13 = try encryptTLS13(provider, algorithm, &out, "message", &header, &iv, &key);
        const plain13 = try decryptTLS13(provider, algorithm, encrypted13, &header, &iv, &key);
        try testing.expectEqualStrings("message", plain13);
        try testing.expectError(error.OutputTooSmall, encryptTLS13(provider, algorithm, out[0..16], "message", &header, &iv, &key));
        try testing.expectError(error.TlsDecryptError, decryptTLS13(provider, algorithm, out[0..15], &header, &iv, &key));
    }
}

test "standalone TLS helpers preserve every selected-provider failure without fallback" {
    const testing = std.testing;
    const Rejected = struct {
        fn kdf(_: *anyopaque, _: p.HashAlgorithm, _: []const u8, _: []const []const u8, _: []u8) p.ProviderError!void {
            return error.InternalError;
        }
        fn prf(_: *anyopaque, _: p.HashAlgorithm, _: []const u8, _: []const u8, _: []const []const u8, _: []u8) p.ProviderError!void {
            return error.InternalError;
        }
        fn hash(_: *anyopaque, _: std.mem.Allocator, _: p.HashAlgorithm, _: *?*anyopaque) p.ProviderError!void {
            return error.InternalError;
        }
        fn seal(_: *anyopaque, _: p.AeadAlgorithm, _: []const u8, _: []const u8, _: []const []const u8, _: []const u8, _: []u8, _: []u8) p.ProviderError!void {
            return error.InternalError;
        }
        fn open(_: *anyopaque, _: p.AeadAlgorithm, _: []const u8, _: []const u8, _: []const []const u8, _: []const u8, _: []const u8, _: []u8) p.ProviderError!void {
            return error.InternalError;
        }
    };
    var standard = @import("standard.zig").StandardProvider.init(testing.io, testing.allocator);
    var provider = standard.provider();
    var vtable = provider.vtable.*;
    provider.vtable = &vtable;
    const random: [32]u8 = @splat(1);
    const master: [48]u8 = @splat(2);
    var out: [48]u8 = @splat(3);
    vtable.tls12Prf = Rejected.prf;
    try testing.expectError(error.InternalError, hmacSha256Expand(provider, "key", "label", "seed", &out));
    try testing.expectEqualSlices(u8, &(@as([48]u8, @splat(0))), &out);
    try testing.expectError(error.InternalError, hmacSha384Expand(provider, "key", "label", "seed", &out));
    try testing.expectError(error.InternalError, deriveMasterSecret256(provider, "secret", &random, &random));
    try testing.expectError(error.InternalError, deriveMasterSecret384(provider, "secret", &random, &random));
    try testing.expectError(error.InternalError, deriveKeyBlock256(provider, &master, &random, &random, 16));
    try testing.expectError(error.InternalError, deriveKeyBlock384(provider, &master, &random, &random, 16));
    vtable.hkdfExpand = Rejected.kdf;
    try testing.expectError(error.InternalError, hkdfExpandLabel(provider, &random, "key", "", 16));
    try testing.expectError(error.InternalError, deriveTrafficKeys13(provider, &random));
    vtable.hkdfExpand = standard.provider().vtable.hkdfExpand;
    vtable.hashCreate = Rejected.hash;
    try testing.expectError(error.InternalError, deriveHandshakeSecret13(provider, testing.allocator, "secret", 32));
    vtable.hkdfExtract = Rejected.kdf;
    try testing.expectError(error.InternalError, hkdfExtract(provider, "ikm", "salt", 32));
    vtable.aeadSeal = Rejected.seal;
    vtable.aeadOpen = Rejected.open;
    const header: [5]u8 = .{ 23, 3, 3, 0, 23 };
    const iv: [12]u8 = @splat(4);
    const key: [16]u8 = @splat(5);
    try testing.expectError(error.InternalError, encryptTLS13(provider, .aes_128_gcm, &out, "message", &header, &iv, &key));
    try testing.expectError(error.InternalError, decryptTLS13(provider, .aes_128_gcm, out[0..23], &header, &iv, &key));
    try testing.expectError(error.InternalError, encryptTLS12(provider, .aes_128_gcm, &out, "message", &header, 0, &iv, &key));
    try testing.expectError(error.InternalError, decryptTLS12(provider, .aes_128_gcm, out[0..31], &header, 0, &iv, &key));
}
