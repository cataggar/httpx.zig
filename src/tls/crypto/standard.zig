//! Pure Zig primitive implementation. This is not a certificate trust policy.
//!
//! The owner, its Io implementation, and its scratch allocator must outlive
//! every borrowed descriptor and handle. Concurrent calls require a concurrent
//! Io implementation and thread-safe scratch allocator. Individual mutable
//! handles must not be used concurrently.
const std = @import("std");
const p = @import("provider.zig");
const der = @import("der.zig");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const Error = p.ProviderError;
const Ecdsa256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const Ecdsa384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = crypto.sign.Ed25519;
const X25519 = crypto.dh.X25519;
const MLKem768 = crypto.kem.ml_kem.MLKem768;

pub const StandardProvider = struct {
    io: std.Io,
    scratch_allocator: Allocator,

    pub fn init(io: std.Io, scratch_allocator: Allocator) StandardProvider {
        return .{ .io = io, .scratch_allocator = scratch_allocator };
    }

    pub fn provider(self: *StandardProvider) p.CryptoProvider {
        return p.CryptoProvider.init(self, &vtable);
    }
};

fn owner(context: *anyopaque) *const StandardProvider {
    return @ptrCast(@alignCast(context));
}

fn cast(comptime T: type, raw: *anyopaque) *T {
    return @ptrCast(@alignCast(raw));
}

fn destroy(comptime T: type, allocator: Allocator, raw: *anyopaque) void {
    const value = cast(T, raw);
    p.secureWipeValue(value);
    allocator.destroy(value);
}

fn Hash(comptime algorithm: p.HashAlgorithm) type {
    return switch (algorithm) {
        .sha1 => crypto.hash.Sha1,
        .sha256 => crypto.hash.sha2.Sha256,
        .sha384 => crypto.hash.sha2.Sha384,
        .sha512 => crypto.hash.sha2.Sha512,
    };
}

const HashState = union(p.HashAlgorithm) {
    sha1: Hash(.sha1),
    sha256: Hash(.sha256),
    sha384: Hash(.sha384),
    sha512: Hash(.sha512),
};

fn capabilities(_: *anyopaque) p.Capabilities {
    var result = p.Capabilities.all();
    // std.crypto has RSA verification, but no RSA private-key signing.
    result.signature_sign = 0;
    result.setSign(.ecdsa_secp256r1_sha256, true);
    result.setSign(.ecdsa_secp384r1_sha384, true);
    result.setSign(.ed25519, true);
    return result;
}

fn random(context: *anyopaque, out: []u8) Error!void {
    owner(context).io.randomSecure(out) catch return error.EntropyUnavailable;
}

fn hashCreate(_: *anyopaque, allocator: Allocator, algorithm: p.HashAlgorithm, out: *?*anyopaque) Error!void {
    const state = try allocator.create(HashState);
    state.* = switch (algorithm) {
        inline else => |a| @unionInit(HashState, @tagName(a), Hash(a).init(.{})),
    };
    out.* = state;
}

fn hashUpdate(_: *anyopaque, raw: *anyopaque, data: []const u8) Error!void {
    switch (cast(HashState, raw).*) {
        inline else => |*state| state.update(data),
    }
}

fn hashSnapshot(_: *anyopaque, raw: *anyopaque, out: []u8) Error!void {
    var snapshot = cast(HashState, raw).*;
    defer p.secureWipeValue(&snapshot);
    switch (snapshot) {
        inline else => |*state, a| state.final(out[0..Hash(a).digest_length]),
    }
}

fn hashClone(_: *anyopaque, raw: *anyopaque, allocator: Allocator, out: *?*anyopaque) Error!void {
    const state = try allocator.create(HashState);
    state.* = cast(HashState, raw).*;
    out.* = state;
}

fn hashDestroy(_: *anyopaque, allocator: Allocator, raw: *anyopaque) void {
    destroy(HashState, allocator, raw);
}

fn hmac(_: *anyopaque, algorithm: p.HashAlgorithm, key: []const u8, parts: []const []const u8, out: []u8) Error!void {
    switch (algorithm) {
        inline else => |a| {
            const Hmac = crypto.auth.hmac.Hmac(Hash(a));
            var state = Hmac.init(key);
            defer p.secureWipeValue(&state);
            for (parts) |part| state.update(part);
            state.final(out[0..Hmac.mac_length]);
        },
    }
}

fn hkdfExtract(context: *anyopaque, algorithm: p.HashAlgorithm, salt: []const u8, parts: []const []const u8, out: []u8) Error!void {
    return hmac(context, algorithm, salt, parts, out);
}

fn hkdfExpand(_: *anyopaque, algorithm: p.HashAlgorithm, prk: []const u8, info_parts: []const []const u8, out: []u8) Error!void {
    switch (algorithm) {
        inline else => |a| {
            const Hmac = crypto.auth.hmac.Hmac(Hash(a));
            var block: [Hmac.mac_length]u8 = undefined;
            defer p.secureWipe(&block);
            var offset: usize = 0;
            var counter: u16 = 1;
            while (offset < out.len) : (counter += 1) {
                var state = Hmac.init(prk);
                defer p.secureWipeValue(&state);
                if (offset != 0) state.update(&block);
                for (info_parts) |part| state.update(part);
                state.update(&.{@intCast(counter)});
                state.final(&block);
                const n = @min(block.len, out.len - offset);
                @memcpy(out[offset..][0..n], block[0..n]);
                offset += n;
            }
        },
    }
}

fn tls12Prf(_: *anyopaque, algorithm: p.HashAlgorithm, secret: []const u8, label: []const u8, seed_parts: []const []const u8, out: []u8) Error!void {
    switch (algorithm) {
        inline else => |a| {
            const Hmac = crypto.auth.hmac.Hmac(Hash(a));
            var a_block: [Hmac.mac_length]u8 = undefined;
            var block: [Hmac.mac_length]u8 = undefined;
            defer p.secureWipe(&a_block);
            defer p.secureWipe(&block);
            var initial = Hmac.init(secret);
            defer p.secureWipeValue(&initial);
            initial.update(label);
            for (seed_parts) |part| initial.update(part);
            initial.final(&a_block);
            var offset: usize = 0;
            while (offset < out.len) {
                var state = Hmac.init(secret);
                defer p.secureWipeValue(&state);
                state.update(&a_block);
                state.update(label);
                for (seed_parts) |part| state.update(part);
                state.final(&block);
                const n = @min(block.len, out.len - offset);
                @memcpy(out[offset..][0..n], block[0..n]);
                offset += n;
                var next = Hmac.init(secret);
                defer p.secureWipeValue(&next);
                next.update(&a_block);
                next.final(&a_block);
            }
        },
    }
}

fn Aead(comptime algorithm: p.AeadAlgorithm) type {
    return switch (algorithm) {
        .aes_128_gcm => crypto.aead.aes_gcm.Aes128Gcm,
        .aes_256_gcm => crypto.aead.aes_gcm.Aes256Gcm,
        .chacha20_poly1305 => crypto.aead.chacha_poly.ChaCha20Poly1305,
    };
}

fn validateAeadLengths(algorithm: p.AeadAlgorithm, payload_len: usize, aad_len: usize) Error!void {
    const max_payload: u64 = switch (algorithm) {
        .aes_128_gcm, .aes_256_gcm => 16 * (@as(u64, 1 << 32) - 2),
        .chacha20_poly1305 => 64 * (@as(u64, 1 << 32) - 1),
    };
    if (payload_len > max_payload or aad_len > std.math.maxInt(u64) / 8)
        return error.InvalidInput;
}

const Aad = struct {
    bytes: []const u8,
    owned: ?[]u8 = null,

    fn init(allocator: Allocator, parts: []const []const u8) Error!Aad {
        if (parts.len == 0) return .{ .bytes = &.{} };
        if (parts.len == 1) return .{ .bytes = parts[0] };
        var length: usize = 0;
        for (parts) |part| length = std.math.add(usize, length, part.len) catch return error.InvalidInput;
        const bytes = try allocator.alloc(u8, length);
        var offset: usize = 0;
        for (parts) |part| {
            @memcpy(bytes[offset..][0..part.len], part);
            offset += part.len;
        }
        return .{ .bytes = bytes, .owned = bytes };
    }

    fn deinit(self: Aad, allocator: Allocator) void {
        if (self.owned) |bytes| allocator.free(bytes);
    }
};

fn aeadSeal(context: *anyopaque, algorithm: p.AeadAlgorithm, key: []const u8, nonce: []const u8, aad_parts: []const []const u8, plaintext: []const u8, ciphertext: []u8, tag: []u8) Error!void {
    try validateAeadLengths(algorithm, plaintext.len, 0);
    const allocator = owner(context).scratch_allocator;
    const aad = try Aad.init(allocator, aad_parts);
    defer aad.deinit(allocator);
    try validateAeadLengths(algorithm, plaintext.len, aad.bytes.len);
    switch (algorithm) {
        inline else => |a| Aead(a).encrypt(ciphertext, tag[0..16], plaintext, aad.bytes, nonce[0..12].*, key[0..Aead(a).key_length].*),
    }
}

fn aeadOpen(context: *anyopaque, algorithm: p.AeadAlgorithm, key: []const u8, nonce: []const u8, aad_parts: []const []const u8, ciphertext: []const u8, tag: []const u8, plaintext: []u8) Error!void {
    try validateAeadLengths(algorithm, ciphertext.len, 0);
    const allocator = owner(context).scratch_allocator;
    const aad = try Aad.init(allocator, aad_parts);
    defer aad.deinit(allocator);
    try validateAeadLengths(algorithm, ciphertext.len, aad.bytes.len);
    switch (algorithm) {
        inline else => |a| Aead(a).decrypt(plaintext, ciphertext, tag[0..16].*, aad.bytes, nonce[0..12].*, key[0..Aead(a).key_length].*) catch return error.AuthenticationFailed,
    }
}

const AgreementState = union(p.KeyAgreementAlgorithm) {
    secp256r1: Ecdsa256.KeyPair,
    secp384r1: Ecdsa384.KeyPair,
    x25519: X25519.KeyPair,
};

fn keyAgreementGenerate(context: *anyopaque, allocator: Allocator, algorithm: p.KeyAgreementAlgorithm, out: *?*anyopaque) Error!void {
    const state = try allocator.create(AgreementState);
    errdefer destroy(AgreementState, allocator, state);
    state.* = switch (algorithm) {
        .x25519 => blk: {
            var seed: [X25519.seed_length]u8 = undefined;
            defer p.secureWipe(&seed);
            try random(context, &seed);
            break :blk .{ .x25519 = X25519.KeyPair.generateDeterministic(seed) catch return error.KeyGenerationFailed };
        },
        inline .secp256r1, .secp384r1 => |a| blk: {
            const Ecdsa = if (a == .secp256r1) Ecdsa256 else Ecdsa384;
            var seed: [Ecdsa.KeyPair.seed_length]u8 = undefined;
            defer p.secureWipe(&seed);
            try random(context, &seed);
            break :blk @unionInit(AgreementState, @tagName(a), Ecdsa.KeyPair.generateDeterministic(seed) catch return error.KeyGenerationFailed);
        },
    };
    out.* = state;
}

fn keyAgreementPublicKey(_: *anyopaque, raw: *anyopaque, out: []u8) Error!void {
    switch (cast(AgreementState, raw).*) {
        .x25519 => |*key| @memcpy(out, &key.public_key),
        inline .secp256r1, .secp384r1 => |*key| @memcpy(out, &key.public_key.toUncompressedSec1()),
    }
}

fn keyAgreementAgree(_: *anyopaque, raw: *anyopaque, peer: []const u8, out: []u8) Error!void {
    switch (cast(AgreementState, raw).*) {
        .x25519 => |*key| {
            var secret = X25519.scalarmult(key.secret_key, peer[0..32].*) catch return error.KeyAgreementFailed;
            defer p.secureWipe(&secret);
            @memcpy(out, &secret);
        },
        inline .secp256r1, .secp384r1 => |*key, a| {
            const Curve = if (a == .secp256r1) crypto.ecc.P256 else crypto.ecc.P384;
            const point = Curve.fromSec1(peer) catch return error.KeyAgreementFailed;
            var shared = point.mul(key.secret_key.bytes, .big) catch return error.KeyAgreementFailed;
            defer p.secureWipeValue(&shared);
            var coordinates = shared.affineCoordinates();
            defer p.secureWipeValue(&coordinates);
            var secret = coordinates.x.toBytes(.big);
            defer p.secureWipe(&secret);
            @memcpy(out, &secret);
        },
    }
}

fn keyAgreementDestroy(_: *anyopaque, allocator: Allocator, raw: *anyopaque) void {
    destroy(AgreementState, allocator, raw);
}

fn kemGenerate(context: *anyopaque, allocator: Allocator, _: p.KemAlgorithm, out: *?*anyopaque) Error!void {
    const key = try allocator.create(MLKem768.KeyPair);
    errdefer destroy(MLKem768.KeyPair, allocator, key);
    var seed: [MLKem768.seed_length]u8 = undefined;
    defer p.secureWipe(&seed);
    try random(context, &seed);
    key.* = MLKem768.KeyPair.generateDeterministic(seed) catch return error.KeyGenerationFailed;
    out.* = key;
}

fn kemPublicKey(_: *anyopaque, raw: *anyopaque, out: []u8) Error!void {
    @memcpy(out, &cast(MLKem768.KeyPair, raw).public_key.toBytes());
}

fn kemEncapsulate(context: *anyopaque, _: p.KemAlgorithm, encoded_key: []const u8, ciphertext: []u8, shared_secret: []u8) Error!void {
    const key = MLKem768.PublicKey.fromBytes(encoded_key[0..MLKem768.PublicKey.encoded_length]) catch return error.EncapsulationFailed;
    var seed: [MLKem768.encaps_seed_length]u8 = undefined;
    defer p.secureWipe(&seed);
    try random(context, &seed);
    var result = key.encapsDeterministic(&seed);
    defer p.secureWipeValue(&result);
    @memcpy(ciphertext, &result.ciphertext);
    @memcpy(shared_secret, &result.shared_secret);
}

fn kemDecapsulate(_: *anyopaque, raw: *anyopaque, ciphertext: []const u8, shared_secret: []u8) Error!void {
    var result = cast(MLKem768.KeyPair, raw).secret_key.decaps(ciphertext[0..MLKem768.ciphertext_length]) catch return error.DecapsulationFailed;
    defer p.secureWipe(&result);
    @memcpy(shared_secret, &result);
}

fn kemDestroy(_: *anyopaque, allocator: Allocator, raw: *anyopaque) void {
    destroy(MLKem768.KeyPair, allocator, raw);
}

const SigningState = union(enum) {
    ecdsa_p256: Ecdsa256.KeyPair,
    ecdsa_p384: Ecdsa384.KeyPair,
    ed25519: Ed25519.KeyPair,
};

fn signingKeyImport(_: *anyopaque, allocator: Allocator, input: p.PrivateKey, out: *?*anyopaque) Error!void {
    if (input.encoding != .raw_secret) return error.UnsupportedOperation;
    const key = try allocator.create(SigningState);
    errdefer destroy(SigningState, allocator, key);
    key.* = switch (input.algorithm) {
        inline .ecdsa_p256, .ecdsa_p384 => |a| blk: {
            const Curve = if (a == .ecdsa_p256) crypto.ecc.P256 else crypto.ecc.P384;
            const Ecdsa = if (a == .ecdsa_p256) Ecdsa256 else Ecdsa384;
            var bytes = input.bytes[0..Ecdsa.SecretKey.encoded_length].*;
            defer p.secureWipe(&bytes);
            // fromSecretKey multiplies modulo the order; reject noncanonical
            // imported scalars rather than silently normalizing a private key.
            var scalar = Curve.scalar.Scalar.fromBytes(bytes, .big) catch return error.InvalidEncoding;
            defer p.secureWipeValue(&scalar);
            if (scalar.isZero()) return error.InvalidEncoding;
            break :blk @unionInit(SigningState, @tagName(a), Ecdsa.KeyPair.fromSecretKey(.{ .bytes = bytes }) catch return error.InvalidEncoding);
        },
        .ed25519 => .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(input.bytes[0..32].*) catch return error.InvalidEncoding },
        .rsa, .rsa_pss => return error.UnsupportedAlgorithm,
    };
    out.* = key;
}

fn sign(context: *anyopaque, raw: *anyopaque, _: p.SignatureScheme, parts: []const []const u8, out: []u8) Error!usize {
    switch (cast(SigningState, raw).*) {
        inline .ecdsa_p256, .ecdsa_p384 => |*key, a| {
            const Ecdsa = if (a == .ecdsa_p256) Ecdsa256 else Ecdsa384;
            var noise: [Ecdsa.noise_length]u8 = undefined;
            defer p.secureWipe(&noise);
            try random(context, &noise);
            var signer = key.signer(noise) catch return error.SigningFailed;
            defer p.secureWipeValue(&signer);
            for (parts) |part| signer.update(part);
            const signature = signer.finalize() catch return error.SigningFailed;
            return signature.toDer(out[0..Ecdsa.Signature.der_encoded_length_max]).len;
        },
        .ed25519 => |*key| {
            var base_nonce: [32]u8 = undefined;
            defer p.secureWipe(&base_nonce);
            try random(context, &base_nonce);
            var signer = key.signerWithBaseNonce(base_nonce, null) catch return error.SigningFailed;
            defer p.secureWipeValue(&signer);
            for (parts) |part| signer.update(part);
            const signature = signer.finalize();
            @memcpy(out[0..64], &signature.toBytes());
            return 64;
        },
    }
}

fn signingKeyDestroy(_: *anyopaque, allocator: Allocator, raw: *anyopaque) void {
    destroy(SigningState, allocator, raw);
}

fn verify(_: *anyopaque, scheme: p.SignatureScheme, public_key: p.PublicKey, parts: []const []const u8, signature: []const u8) Error!void {
    switch (scheme) {
        inline .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 => |s| {
            const Ecdsa = if (s == .ecdsa_secp256r1_sha256) Ecdsa256 else Ecdsa384;
            const sig = Ecdsa.Signature.fromDer(signature) catch return error.InvalidEncoding;
            const key = Ecdsa.PublicKey.fromSec1(public_key.bytes) catch return error.InvalidEncoding;
            var verifier = sig.verifier(key) catch return error.SignatureInvalid;
            for (parts) |part| verifier.update(part);
            verifier.verify() catch return error.SignatureInvalid;
        },
        .ed25519 => {
            const sig = Ed25519.Signature.fromBytes(signature[0..64].*);
            const key = Ed25519.PublicKey.fromBytes(public_key.bytes[0..32].*) catch return error.InvalidEncoding;
            var verifier = sig.verifier(key) catch return error.SignatureInvalid;
            for (parts) |part| verifier.update(part);
            verifier.verify() catch return error.SignatureInvalid;
        },
        inline else => |s| {
            const Rsa = crypto.Certificate.rsa;
            const Signature = switch (s) {
                .rsa_pkcs1_sha1, .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 => Rsa.PKCS1v1_5Signature,
                else => Rsa.PSSSignature,
            };
            try der.validateRsaPublicKey(public_key.bytes);
            const components = Rsa.PublicKey.parseDer(public_key.bytes) catch return error.InvalidEncoding;
            if (components.modulus[0] & 0x80 == 0) return error.UnsupportedAlgorithm;
            if (signature.len != components.modulus.len) return error.InvalidSignatureLength;
            const key = Rsa.PublicKey.fromBytes(components.exponent, components.modulus) catch return error.InvalidEncoding;
            // Match the supported std TLS RSA modulus sizes, excluding 1024-bit keys.
            switch (components.modulus.len) {
                inline 256, 384, 512 => |length| {
                    const sig = Signature.fromBytes(length, signature);
                    Signature.concatVerify(length, sig, parts, key, Hash(s.hashAlgorithm().?)) catch return error.SignatureInvalid;
                },
                else => return error.UnsupportedAlgorithm,
            }
        },
    }
}

fn constantTimeEqual(_: *anyopaque, a: []const u8, b: []const u8) Error!bool {
    var equal: u1 = 1;
    var offset: usize = 0;
    while (a.len - offset >= 32) : (offset += 32) {
        equal &= @intFromBool(crypto.timing_safe.eql([32]u8, a[offset..][0..32].*, b[offset..][0..32].*));
    }
    var left: [32]u8 = @splat(0);
    var right: [32]u8 = @splat(0);
    defer p.secureWipe(&left);
    defer p.secureWipe(&right);
    @memcpy(left[0 .. a.len - offset], a[offset..]);
    @memcpy(right[0 .. b.len - offset], b[offset..]);
    equal &= @intFromBool(crypto.timing_safe.eql([32]u8, left, right));
    return equal == 1;
}

const vtable: p.VTable = .{
    .capabilities = capabilities,
    .random = random,
    .hashCreate = hashCreate,
    .hashUpdate = hashUpdate,
    .hashSnapshot = hashSnapshot,
    .hashClone = hashClone,
    .hashDestroy = hashDestroy,
    .hmac = hmac,
    .hkdfExtract = hkdfExtract,
    .hkdfExpand = hkdfExpand,
    .tls12Prf = tls12Prf,
    .aeadSeal = aeadSeal,
    .aeadOpen = aeadOpen,
    .keyAgreementGenerate = keyAgreementGenerate,
    .keyAgreementPublicKey = keyAgreementPublicKey,
    .keyAgreementAgree = keyAgreementAgree,
    .keyAgreementDestroy = keyAgreementDestroy,
    .kemGenerate = kemGenerate,
    .kemPublicKey = kemPublicKey,
    .kemEncapsulate = kemEncapsulate,
    .kemDecapsulate = kemDecapsulate,
    .kemDestroy = kemDestroy,
    .signingKeyImport = signingKeyImport,
    .sign = sign,
    .signingKeyDestroy = signingKeyDestroy,
    .verify = verify,
    .constantTimeEqual = constantTimeEqual,
};

test "standard AEAD length limits prevent counter and bit length overflow" {
    if (@bitSizeOf(usize) < 64) return;
    try std.testing.expectError(error.InvalidInput, validateAeadLengths(.aes_128_gcm, 16 * (@as(usize, 1 << 32) - 2) + 1, 0));
    try std.testing.expectError(error.InvalidInput, validateAeadLengths(.chacha20_poly1305, 64 * (@as(usize, 1 << 32) - 1) + 1, 0));
    try std.testing.expectError(error.InvalidInput, validateAeadLengths(.aes_256_gcm, 0, std.math.maxInt(u64) / 8 + 1));
}
