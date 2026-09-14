//! HTTPX-owned TLS cryptographic state. All operations dispatch through the
//! selected provider; the types below contain only metadata and owned state.
const std = @import("std");
const p = @import("provider.zig");
pub fn HashType(comptime algorithm: p.HashAlgorithm) type {
    return struct {
        handle: p.HashHandle,
        pub const digest_length: comptime_int = algorithm.digestLength();
        pub const hash_algorithm = algorithm;

        pub fn init(provider: p.CryptoProvider, allocator: std.mem.Allocator) p.ProviderError!@This() {
            return .{ .handle = try provider.hashCreate(allocator, algorithm) };
        }

        pub fn update(self: *@This(), bytes: []const u8) p.ProviderError!void {
            try self.handle.update(bytes);
        }

        pub fn peek(self: *@This()) p.ProviderError![digest_length]u8 {
            var digest: [digest_length]u8 = undefined;
            try self.handle.snapshot(&digest);
            return digest;
        }

        pub fn finalResult(self: *@This()) p.ProviderError![digest_length]u8 {
            return self.peek();
        }

        pub fn clone(self: *@This(), allocator: std.mem.Allocator) p.ProviderError!@This() {
            return .{ .handle = try self.handle.clone(allocator) };
        }

        pub fn deinit(self: *@This()) void {
            self.handle.deinit();
        }
    };
}

pub fn Aead(comptime algorithm: p.AeadAlgorithm) type {
    return struct {
        pub const key_length: comptime_int = algorithm.keyLength();
        pub const nonce_length: comptime_int = p.AeadAlgorithm.nonce_length;
        pub const tag_length: comptime_int = p.AeadAlgorithm.tag_length;
        pub const aead_algorithm = algorithm;

        pub fn encrypt(provider: p.CryptoProvider, ciphertext: []u8, tag: *[tag_length]u8, plaintext: []const u8, aad: []const u8, nonce: [nonce_length]u8, key: [key_length]u8) p.ProviderError!void {
            return provider.aeadSeal(algorithm, &key, &nonce, &.{aad}, plaintext, ciphertext, tag);
        }

        pub fn decrypt(provider: p.CryptoProvider, plaintext: []u8, ciphertext: []const u8, tag: [tag_length]u8, aad: []const u8, nonce: [nonce_length]u8, key: [key_length]u8) p.ProviderError!void {
            return provider.aeadOpen(algorithm, &key, &nonce, &.{aad}, ciphertext, &tag, plaintext);
        }
    };
}

pub fn HmacType(comptime algorithm: p.HashAlgorithm) type {
    return struct {
        pub const hash_algorithm = algorithm;
        pub const mac_length: comptime_int = algorithm.digestLength();
        pub const key_length = mac_length;
        pub const key_length_min = 0;
    };
}

pub fn HkdfType(comptime algorithm: p.HashAlgorithm) type {
    return struct {
        pub const hash_algorithm = algorithm;
        pub const prk_length: comptime_int = algorithm.digestLength();

        pub fn extract(provider: p.CryptoProvider, salt: []const u8, ikm: []const u8) p.ProviderError![prk_length]u8 {
            var prk: [prk_length]u8 = undefined;
            try provider.hkdfExtract(algorithm, salt, &.{ikm}, &prk);
            return prk;
        }
    };
}

pub fn hmac(provider: p.CryptoProvider, comptime H: type, message: []const u8, key: []const u8) p.ProviderError![H.mac_length]u8 {
    var mac: [H.mac_length]u8 = undefined;
    try provider.hmac(H.hash_algorithm, key, &.{message}, &mac);
    return mac;
}

pub fn emptyHash(provider: p.CryptoProvider, allocator: std.mem.Allocator, comptime H: type) p.ProviderError![H.digest_length]u8 {
    var hash = try H.init(provider, allocator);
    defer hash.deinit();
    return hash.peek();
}

pub fn hmacExpandLabel(provider: p.CryptoProvider, comptime H: type, secret: []const u8, label_then_seed: []const []const u8, comptime len: usize) p.ProviderError![len]u8 {
    if (label_then_seed.len == 0) return error.InvalidInput;
    var out: [len]u8 = undefined;
    try provider.tls12Prf(H.hash_algorithm, secret, label_then_seed[0], label_then_seed[1..], &out);
    return out;
}

pub fn hkdfExpandLabel(provider: p.CryptoProvider, comptime K: type, secret: [K.prk_length]u8, label: []const u8, context: []const u8, comptime len: usize) p.ProviderError![len]u8 {
    if (label.len > 249 or context.len > 255 or len > std.math.maxInt(u16))
        return error.InvalidInput;
    var info: [2 + 1 + 255 + 1 + 255]u8 = undefined;
    std.mem.writeInt(u16, info[0..2], len, .big);
    info[2] = @intCast(6 + label.len);
    @memcpy(info[3..9], "tls13 ");
    @memcpy(info[9..][0..label.len], label);
    info[9 + label.len] = @intCast(context.len);
    @memcpy(info[10 + label.len ..][0..context.len], context);
    var out: [len]u8 = undefined;
    try provider.hkdfExpand(K.hash_algorithm, &secret, &.{info[0 .. 10 + label.len + context.len]}, &out);
    return out;
}

pub fn ApplicationCipherT(comptime aead: p.AeadAlgorithm, comptime hash: p.HashAlgorithm, comptime explicit_iv_length: comptime_int) type {
    return union {
        pub const AEAD = Aead(aead);
        pub const Hash = HashType(hash);
        pub const Hmac = HmacType(hash);
        pub const Hkdf = HkdfType(hash);
        pub const enc_key_length = AEAD.key_length;
        pub const fixed_iv_length = AEAD.nonce_length - explicit_iv_length;
        pub const record_iv_length = explicit_iv_length;
        pub const mac_length = AEAD.tag_length;
        pub const mac_key_length = 0;
        pub const verify_data_length = 12;

        tls_1_2: Tls_1_2,
        tls_1_3: Tls_1_3,

        pub const Tls_1_2 = extern struct {
            client_write_MAC_key: [mac_key_length]u8,
            server_write_MAC_key: [mac_key_length]u8,
            client_write_key: [enc_key_length]u8,
            server_write_key: [enc_key_length]u8,
            client_write_IV: [fixed_iv_length]u8,
            server_write_IV: [fixed_iv_length]u8,
            client_salt: [record_iv_length]u8,
        };

        pub const Tls_1_3 = struct {
            client_secret: [Hash.digest_length]u8,
            server_secret: [Hash.digest_length]u8,
            client_key: [AEAD.key_length]u8,
            server_key: [AEAD.key_length]u8,
            client_iv: [AEAD.nonce_length]u8,
            server_iv: [AEAD.nonce_length]u8,
        };
    };
}

fn HandshakeCipherT(comptime aead: p.AeadAlgorithm, comptime hash: p.HashAlgorithm, comptime explicit_iv_length: comptime_int) type {
    return struct {
        pub const A = ApplicationCipherT(aead, hash, explicit_iv_length);
        transcript_hash: A.Hash,
        version: union {
            tls_1_2: struct {
                expected_server_verify_data: [A.verify_data_length]u8,
                app_cipher: A.Tls_1_2,
            },
            tls_1_3: struct {
                handshake_secret: [A.Hkdf.prk_length]u8,
                master_secret: [A.Hkdf.prk_length]u8,
                client_handshake_key: [A.AEAD.key_length]u8,
                server_handshake_key: [A.AEAD.key_length]u8,
                client_finished_key: [A.Hmac.key_length]u8,
                server_finished_key: [A.Hmac.key_length]u8,
                client_handshake_iv: [A.AEAD.nonce_length]u8,
                server_handshake_iv: [A.AEAD.nonce_length]u8,
            },
        },
    };
}

pub const HandshakeCipher = union(enum) {
    AES_128_GCM_SHA256: HandshakeCipherT(.aes_128_gcm, .sha256, 8),
    AES_256_GCM_SHA384: HandshakeCipherT(.aes_256_gcm, .sha384, 8),
    CHACHA20_POLY1305_SHA256: HandshakeCipherT(.chacha20_poly1305, .sha256, 0),

    pub fn deinit(self: *HandshakeCipher) void {
        switch (self.*) {
            inline else => |*value| value.transcript_hash.deinit(),
        }
        p.secureWipeValue(self);
    }
};

pub const ApplicationCipher = union(enum) {
    AES_128_GCM_SHA256: ApplicationCipherT(.aes_128_gcm, .sha256, 8),
    AES_256_GCM_SHA384: ApplicationCipherT(.aes_256_gcm, .sha384, 8),
    CHACHA20_POLY1305_SHA256: ApplicationCipherT(.chacha20_poly1305, .sha256, 0),
};
