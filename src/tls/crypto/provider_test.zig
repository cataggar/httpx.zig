const std = @import("std");
const p = @import("provider.zig");

const operation_count = @typeInfo(p.Operation).@"enum".fields.len;

const FakeHandle = struct {
    algorithm_tag: u16,
    state: u64 = 0,
    secret: [32]u8 = [_]u8{0xa5} ** 32,
};

const FakeProvider = struct {
    caps: p.Capabilities = p.Capabilities.all(),
    calls: [operation_count]usize = [_]usize{0} ** operation_count,
    fail: ?p.Operation = null,
    partial_fail: ?p.Operation = null,
    authentication_failure: bool = false,
    signature_invalid: bool = false,
    destroy_wipes: usize = 0,

    fn descriptor(self: *FakeProvider) p.CryptoProvider {
        return p.CryptoProvider.init(self, &vtable);
    }

    fn fromContext(context: *anyopaque) *FakeProvider {
        return @ptrCast(@alignCast(context));
    }

    fn handle(raw: *anyopaque) *FakeHandle {
        return @ptrCast(@alignCast(raw));
    }

    fn bump(self: *FakeProvider, operation: p.Operation) void {
        self.calls[@intFromEnum(operation)] += 1;
    }

    fn count(self: *const FakeProvider, operation: p.Operation) usize {
        return self.calls[@intFromEnum(operation)];
    }

    fn failIfRequested(self: *FakeProvider, operation: p.Operation) p.ProviderError!void {
        if (self.fail == operation) return error.InternalError;
    }

    fn createHandle(
        self: *FakeProvider,
        allocator: std.mem.Allocator,
        operation: p.Operation,
        algorithm_tag: u16,
        out_handle: *?*anyopaque,
    ) p.ProviderError!void {
        self.bump(operation);
        try self.failIfRequested(operation);
        const owned = try allocator.create(FakeHandle);
        owned.* = .{ .algorithm_tag = algorithm_tag };
        out_handle.* = owned;
        if (self.partial_fail == operation) return error.InternalError;
    }

    fn destroyHandle(
        self: *FakeProvider,
        allocator: std.mem.Allocator,
        operation: p.Operation,
        raw: *anyopaque,
    ) void {
        self.bump(operation);
        const owned = handle(raw);
        p.secureWipe(&owned.secret);
        if (std.mem.allEqual(u8, &owned.secret, 0)) self.destroy_wipes += 1;
        allocator.destroy(owned);
    }

    fn capabilities(context: *anyopaque) p.Capabilities {
        const self = fromContext(context);
        self.bump(.capabilities);
        return self.caps;
    }

    fn random(context: *anyopaque, out: []u8) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.random);
        @memset(out, 0xa5);
        try self.failIfRequested(.random);
    }

    fn hashCreate(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        algorithm: p.HashAlgorithm,
        out_handle: *?*anyopaque,
    ) p.ProviderError!void {
        const self = fromContext(context);
        try self.createHandle(allocator, .hash_create, @intFromEnum(algorithm), out_handle);
    }

    fn hashUpdate(context: *anyopaque, raw: *anyopaque, data: []const u8) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.hash_update);
        for (data) |byte| handle(raw).state = handle(raw).state *% 131 +% byte;
        try self.failIfRequested(.hash_update);
    }

    fn hashSnapshot(context: *anyopaque, raw: *anyopaque, out: []u8) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.hash_snapshot);
        @memset(out, @truncate(handle(raw).state));
        try self.failIfRequested(.hash_snapshot);
    }

    fn hashClone(
        context: *anyopaque,
        raw: *anyopaque,
        allocator: std.mem.Allocator,
        out_handle: *?*anyopaque,
    ) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.hash_clone);
        try self.failIfRequested(.hash_clone);
        const cloned = try allocator.create(FakeHandle);
        cloned.* = handle(raw).*;
        out_handle.* = cloned;
        if (self.partial_fail == .hash_clone) return error.InternalError;
    }

    fn hashDestroy(context: *anyopaque, allocator: std.mem.Allocator, raw: *anyopaque) void {
        fromContext(context).destroyHandle(allocator, .hash_destroy, raw);
    }

    fn hmac(
        context: *anyopaque,
        _: p.HashAlgorithm,
        key: []const u8,
        parts: []const []const u8,
        out: []u8,
    ) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.hmac);
        var value: u8 = @truncate(key.len);
        for (parts) |part| value +%= @truncate(part.len);
        @memset(out, value);
        try self.failIfRequested(.hmac);
    }

    fn hkdfExtract(
        context: *anyopaque,
        _: p.HashAlgorithm,
        salt: []const u8,
        ikm_parts: []const []const u8,
        out: []u8,
    ) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.hkdf_extract);
        var value: u8 = @truncate(salt.len);
        for (ikm_parts) |part| value +%= @truncate(part.len);
        @memset(out, value);
        try self.failIfRequested(.hkdf_extract);
    }

    fn hkdfExpand(
        context: *anyopaque,
        _: p.HashAlgorithm,
        _: []const u8,
        info_parts: []const []const u8,
        out: []u8,
    ) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.hkdf_expand);
        var value: u8 = 0;
        for (info_parts) |part| value +%= @truncate(part.len);
        @memset(out, value);
        try self.failIfRequested(.hkdf_expand);
    }

    fn tls12Prf(
        context: *anyopaque,
        _: p.HashAlgorithm,
        _: []const u8,
        label: []const u8,
        seed_parts: []const []const u8,
        out: []u8,
    ) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.tls12_prf);
        var value: u8 = @truncate(label.len);
        for (seed_parts) |part| value +%= @truncate(part.len);
        @memset(out, value);
        try self.failIfRequested(.tls12_prf);
    }

    fn aeadSeal(
        context: *anyopaque,
        _: p.AeadAlgorithm,
        _: []const u8,
        _: []const u8,
        _: []const []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: []u8,
    ) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.aead_seal);
        for (plaintext, ciphertext) |plain, *cipher| cipher.* = plain ^ 0x5a;
        @memset(tag, 0x3c);
        try self.failIfRequested(.aead_seal);
    }

    fn aeadOpen(
        context: *anyopaque,
        _: p.AeadAlgorithm,
        _: []const u8,
        _: []const u8,
        _: []const []const u8,
        ciphertext: []const u8,
        _: []const u8,
        plaintext: []u8,
    ) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.aead_open);
        for (ciphertext, plaintext) |cipher, *plain| plain.* = cipher ^ 0x5a;
        if (self.authentication_failure) return error.AuthenticationFailed;
        try self.failIfRequested(.aead_open);
    }

    fn keyAgreementGenerate(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        algorithm: p.KeyAgreementAlgorithm,
        out_handle: *?*anyopaque,
    ) p.ProviderError!void {
        const self = fromContext(context);
        try self.createHandle(allocator, .key_agreement_generate, @intFromEnum(algorithm), out_handle);
    }

    fn keyAgreementPublicKey(context: *anyopaque, _: *anyopaque, out: []u8) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.key_agreement_public_key);
        @memset(out, 0x11);
        if (out.len > 0 and out.len != 32) out[0] = 0x04;
        try self.failIfRequested(.key_agreement_public_key);
    }

    fn keyAgreementAgree(
        context: *anyopaque,
        _: *anyopaque,
        _: []const u8,
        out: []u8,
    ) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.key_agreement_agree);
        @memset(out, 0x22);
        try self.failIfRequested(.key_agreement_agree);
    }

    fn keyAgreementDestroy(context: *anyopaque, allocator: std.mem.Allocator, raw: *anyopaque) void {
        fromContext(context).destroyHandle(allocator, .key_agreement_destroy, raw);
    }

    fn kemGenerate(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        algorithm: p.KemAlgorithm,
        out_handle: *?*anyopaque,
    ) p.ProviderError!void {
        const self = fromContext(context);
        try self.createHandle(allocator, .kem_generate, @intFromEnum(algorithm), out_handle);
    }

    fn kemPublicKey(context: *anyopaque, _: *anyopaque, out: []u8) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.kem_public_key);
        @memset(out, 0x33);
        try self.failIfRequested(.kem_public_key);
    }

    fn kemEncapsulate(
        context: *anyopaque,
        _: p.KemAlgorithm,
        _: []const u8,
        ciphertext: []u8,
        shared_secret: []u8,
    ) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.kem_encapsulate);
        @memset(ciphertext, 0x44);
        @memset(shared_secret, 0x45);
        try self.failIfRequested(.kem_encapsulate);
    }

    fn kemDecapsulate(
        context: *anyopaque,
        _: *anyopaque,
        _: []const u8,
        shared_secret: []u8,
    ) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.kem_decapsulate);
        @memset(shared_secret, 0x45);
        try self.failIfRequested(.kem_decapsulate);
    }

    fn kemDestroy(context: *anyopaque, allocator: std.mem.Allocator, raw: *anyopaque) void {
        fromContext(context).destroyHandle(allocator, .kem_destroy, raw);
    }

    fn signingKeyImport(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        key: p.PrivateKey,
        out_handle: *?*anyopaque,
    ) p.ProviderError!void {
        const self = fromContext(context);
        try self.createHandle(allocator, .signing_key_import, @intFromEnum(key.algorithm), out_handle);
    }

    fn sign(
        context: *anyopaque,
        _: *anyopaque,
        scheme: p.SignatureScheme,
        _: []const []const u8,
        out: []u8,
    ) p.ProviderError!usize {
        const self = fromContext(context);
        self.bump(.sign);
        switch (scheme.signatureEncoding()) {
            .ecdsa_der => {
                const encoded = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };
                @memcpy(out[0..encoded.len], &encoded);
                try self.failIfRequested(.sign);
                return encoded.len;
            },
            .rsa_raw => {
                if (out.len < 32) return error.OutputTooSmall;
                @memset(out[0..32], 0x55);
                try self.failIfRequested(.sign);
                return 32;
            },
            .ed25519_raw => {
                @memset(out[0..64], 0x66);
                try self.failIfRequested(.sign);
                return 64;
            },
        }
    }

    fn signingKeyDestroy(context: *anyopaque, allocator: std.mem.Allocator, raw: *anyopaque) void {
        fromContext(context).destroyHandle(allocator, .signing_key_destroy, raw);
    }

    fn verify(
        context: *anyopaque,
        _: p.SignatureScheme,
        _: p.PublicKey,
        _: []const []const u8,
        _: []const u8,
    ) p.ProviderError!void {
        const self = fromContext(context);
        self.bump(.verify);
        if (self.signature_invalid) return error.SignatureInvalid;
        try self.failIfRequested(.verify);
    }

    fn constantTimeEqual(
        context: *anyopaque,
        a: []const u8,
        b: []const u8,
    ) p.ProviderError!bool {
        const self = fromContext(context);
        self.bump(.constant_time_equal);
        try self.failIfRequested(.constant_time_equal);
        return std.mem.eql(u8, a, b);
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
};

test "algorithm metadata has exact TLS encodings and sizes" {
    try std.testing.expectEqual(@as(usize, 20), p.HashAlgorithm.sha1.digestLength());
    try std.testing.expectEqual(@as(usize, 32), p.HashAlgorithm.sha256.digestLength());
    try std.testing.expectEqual(@as(usize, 48), p.HashAlgorithm.sha384.digestLength());
    try std.testing.expectEqual(@as(usize, 64), p.HashAlgorithm.sha512.digestLength());
    try std.testing.expectEqual(@as(usize, 64), p.HashAlgorithm.sha256.blockLength());
    try std.testing.expectEqual(@as(usize, 128), p.HashAlgorithm.sha384.blockLength());

    try std.testing.expectEqual(@as(usize, 16), p.AeadAlgorithm.aes_128_gcm.keyLength());
    try std.testing.expectEqual(@as(usize, 32), p.AeadAlgorithm.aes_256_gcm.keyLength());
    try std.testing.expectEqual(@as(usize, 32), p.AeadAlgorithm.chacha20_poly1305.keyLength());
    try std.testing.expectEqual(@as(usize, 12), p.AeadAlgorithm.nonce_length);
    try std.testing.expectEqual(@as(usize, 16), p.AeadAlgorithm.tag_length);

    try std.testing.expectEqual(@as(u16, 0x001d), @intFromEnum(p.KeyAgreementAlgorithm.x25519));
    try std.testing.expectEqual(@as(usize, 32), p.KeyAgreementAlgorithm.x25519.publicKeyLength());
    try std.testing.expectEqual(@as(usize, 65), p.KeyAgreementAlgorithm.secp256r1.publicKeyLength());
    try std.testing.expectEqual(@as(usize, 97), p.KeyAgreementAlgorithm.secp384r1.publicKeyLength());
    try std.testing.expectEqual(@as(usize, 48), p.KeyAgreementAlgorithm.secp384r1.sharedSecretLength());

    try std.testing.expectEqual(@as(usize, 1184), p.KemAlgorithm.ml_kem_768.encapsulationKeyLength());
    try std.testing.expectEqual(@as(usize, 1088), p.KemAlgorithm.ml_kem_768.ciphertextLength());
    try std.testing.expectEqual(@as(usize, 32), p.KemAlgorithm.ml_kem_768.sharedSecretLength());

    try std.testing.expectEqual(@as(u16, 0x0403), @intFromEnum(p.SignatureScheme.ecdsa_secp256r1_sha256));
    try std.testing.expectEqual(@as(u16, 0x080b), @intFromEnum(p.SignatureScheme.rsa_pss_pss_sha512));
    try std.testing.expectEqual(@as(usize, 72), p.SignatureScheme.ecdsa_secp256r1_sha256.signatureCapacity().?);
    try std.testing.expectEqual(@as(usize, 104), p.SignatureScheme.ecdsa_secp384r1_sha384.signatureCapacity().?);
    try std.testing.expectEqual(@as(usize, 64), p.SignatureScheme.ed25519.fixedSignatureLength().?);
    try std.testing.expectEqual(p.SignatureEncoding.rsa_raw, p.SignatureScheme.rsa_pss_rsae_sha384.signatureEncoding());

    const all = p.Capabilities.all();
    inline for (std.meta.fields(p.SignatureScheme)) |field| {
        const scheme: p.SignatureScheme = @enumFromInt(field.value);
        try std.testing.expect(all.supportsSign(scheme));
        try std.testing.expect(all.supportsVerify(scheme));
    }
}

test "capability sets expose independent typed mutation" {
    var caps: p.Capabilities = .{};
    caps.setHash(.sha256, true);
    caps.setHmac(.sha384, true);
    caps.setHkdf(.sha512, true);
    caps.setTls12Prf(.sha256, true);
    caps.setAead(.chacha20_poly1305, true);
    caps.setKeyAgreement(.secp384r1, true);
    caps.setKem(.ml_kem_768, true);
    caps.setSign(.rsa_pss_rsae_sha384, true);
    caps.setVerify(.ed25519, true);

    try std.testing.expect(caps.supportsHash(.sha256));
    try std.testing.expect(!caps.supportsHash(.sha384));
    try std.testing.expect(caps.supportsHmac(.sha384));
    try std.testing.expect(caps.supportsHkdf(.sha512));
    try std.testing.expect(caps.supportsTls12Prf(.sha256));
    try std.testing.expect(caps.supportsAead(.chacha20_poly1305));
    try std.testing.expect(caps.supportsKeyAgreement(.secp384r1));
    try std.testing.expect(caps.supportsKem(.ml_kem_768));
    try std.testing.expect(caps.supportsSign(.rsa_pss_rsae_sha384));
    try std.testing.expect(caps.supportsVerify(.ed25519));

    caps.setSign(.rsa_pss_rsae_sha384, false);
    try std.testing.expect(!caps.supportsSign(.rsa_pss_rsae_sha384));
}

test "fake provider dispatches every contract operation" {
    var fake: FakeProvider = .{};
    const provider = fake.descriptor();
    const allocator = std.testing.allocator;
    const parts = &[_][]const u8{ "one", "two" };

    var random: [8]u8 = undefined;
    try provider.random(&random);

    var hash = try provider.hashCreate(allocator, .sha256);
    defer hash.deinit();
    try hash.update("abc");
    var digest: [32]u8 = undefined;
    try hash.snapshot(&digest);
    var cloned = try hash.clone(allocator);
    defer cloned.deinit();

    var mac: [32]u8 = undefined;
    try provider.hmac(.sha256, "key", parts, &mac);
    var prk: [32]u8 = undefined;
    try provider.hkdfExtract(.sha256, "salt", parts, &prk);
    var okm: [42]u8 = undefined;
    try provider.hkdfExpand(.sha256, &prk, parts, &okm);
    var prf: [48]u8 = undefined;
    try provider.tls12Prf(.sha256, "secret", "label", parts, &prf);

    const aead_key = [_]u8{0x01} ** 16;
    const nonce = [_]u8{0x02} ** 12;
    const plaintext = "payload";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try provider.aeadSeal(.aes_128_gcm, &aead_key, &nonce, parts, plaintext, &ciphertext, &tag);
    var opened: [plaintext.len]u8 = undefined;
    try provider.aeadOpen(.aes_128_gcm, &aead_key, &nonce, parts, &ciphertext, &tag, &opened);
    try std.testing.expectEqualStrings(plaintext, &opened);

    var agreement = try provider.keyAgreementGenerate(allocator, .x25519);
    defer agreement.deinit();
    var agreement_public: [32]u8 = undefined;
    try agreement.publicKey(&agreement_public);
    var agreement_secret: [32]u8 = undefined;
    try agreement.agree(&agreement_public, &agreement_secret);

    var kem = try provider.kemGenerate(allocator, .ml_kem_768);
    defer kem.deinit();
    var kem_public: [1184]u8 = undefined;
    try kem.publicKey(&kem_public);
    var kem_ciphertext: [1088]u8 = undefined;
    var kem_secret: [32]u8 = undefined;
    try provider.kemEncapsulate(.ml_kem_768, &kem_public, &kem_ciphertext, &kem_secret);
    var decapsulated: [32]u8 = undefined;
    try kem.decapsulate(&kem_ciphertext, &decapsulated);
    try std.testing.expectEqualSlices(u8, &kem_secret, &decapsulated);

    const private_bytes = [_]u8{0x77} ** 32;
    var signing_key = try provider.signingKeyImport(allocator, .{
        .algorithm = .ecdsa_p256,
        .encoding = .raw_secret,
        .bytes = &private_bytes,
    });
    defer signing_key.deinit();
    var signature_buf: [72]u8 = undefined;
    const signature = try signing_key.sign(.ecdsa_secp256r1_sha256, parts, &signature_buf);
    const public_bytes = [_]u8{0x04} ++ [_]u8{0x88} ** 64;
    try provider.verify(.ecdsa_secp256r1_sha256, .{
        .algorithm = .ecdsa_p256,
        .encoding = .sec1_uncompressed,
        .bytes = &public_bytes,
    }, parts, signature);

    try std.testing.expect(try provider.constantTimeEqual("same", "same"));

    hash.deinit();
    cloned.deinit();
    agreement.deinit();
    kem.deinit();
    signing_key.deinit();
    try std.testing.expectEqual(@as(usize, 2), fake.count(.hash_destroy));
    try std.testing.expectEqual(@as(usize, 1), fake.count(.key_agreement_destroy));
    try std.testing.expectEqual(@as(usize, 1), fake.count(.kem_destroy));
    try std.testing.expectEqual(@as(usize, 1), fake.count(.signing_key_destroy));
    try std.testing.expectEqual(@as(usize, 5), fake.destroy_wipes);
    inline for (std.meta.fields(p.Operation)) |field| {
        const operation: p.Operation = @enumFromInt(field.value);
        try std.testing.expect(fake.count(operation) > 0);
    }
}

test "hash snapshots are non-destructive and clones fork state" {
    var fake: FakeProvider = .{};
    const provider = fake.descriptor();
    var hash = try provider.hashCreate(std.testing.allocator, .sha256);
    defer hash.deinit();
    try hash.update("a");

    var first: [32]u8 = undefined;
    var repeated: [32]u8 = undefined;
    try hash.snapshot(&first);
    try hash.snapshot(&repeated);
    try std.testing.expectEqualSlices(u8, &first, &repeated);

    var cloned = try hash.clone(std.testing.allocator);
    defer cloned.deinit();
    try hash.update("b");
    try cloned.update("c");
    var original_digest: [32]u8 = undefined;
    var cloned_digest: [32]u8 = undefined;
    try hash.snapshot(&original_digest);
    try cloned.snapshot(&cloned_digest);
    try std.testing.expect(!std.mem.eql(u8, &original_digest, &cloned_digest));

    hash.deinit();
    cloned.deinit();
    try std.testing.expectEqual(@as(usize, 2), fake.count(.hash_destroy));
    try std.testing.expectEqual(@as(usize, 2), fake.destroy_wipes);
}

test "take invalidates source and destroy is idempotent" {
    var fake: FakeProvider = .{};
    const provider = fake.descriptor();
    var source = try provider.hashCreate(std.testing.allocator, .sha256);
    var moved = try source.take();
    try std.testing.expect(!source.isActive());
    try std.testing.expect(moved.isActive());
    try std.testing.expectError(error.InvalidHandle, source.update("no"));
    source.deinit();
    moved.deinit();
    moved.deinit();
    try std.testing.expectEqual(@as(usize, 1), fake.count(.hash_destroy));
}

test "partial handle construction is cleaned through matching destroy paths" {
    const allocator = std.testing.allocator;
    const private_bytes = [_]u8{0x11} ** 32;

    var fake: FakeProvider = .{ .partial_fail = .hash_create };
    try std.testing.expectError(error.InternalError, fake.descriptor().hashCreate(allocator, .sha256));
    try std.testing.expectEqual(@as(usize, 1), fake.count(.hash_destroy));

    fake = .{};
    var hash = try fake.descriptor().hashCreate(allocator, .sha256);
    fake.partial_fail = .hash_clone;
    try std.testing.expectError(error.InternalError, hash.clone(allocator));
    hash.deinit();
    try std.testing.expectEqual(@as(usize, 2), fake.count(.hash_destroy));

    fake = .{ .partial_fail = .key_agreement_generate };
    try std.testing.expectError(error.InternalError, fake.descriptor().keyAgreementGenerate(allocator, .x25519));
    try std.testing.expectEqual(@as(usize, 1), fake.count(.key_agreement_destroy));

    fake = .{ .partial_fail = .kem_generate };
    try std.testing.expectError(error.InternalError, fake.descriptor().kemGenerate(allocator, .ml_kem_768));
    try std.testing.expectEqual(@as(usize, 1), fake.count(.kem_destroy));

    fake = .{ .partial_fail = .signing_key_import };
    try std.testing.expectError(error.InternalError, fake.descriptor().signingKeyImport(allocator, .{
        .algorithm = .ecdsa_p256,
        .encoding = .raw_secret,
        .bytes = &private_bytes,
    }));
    try std.testing.expectEqual(@as(usize, 1), fake.count(.signing_key_destroy));
    try std.testing.expectEqual(@as(usize, 1), fake.destroy_wipes);
}

test "AEAD failure wiping and overlap contract are enforced" {
    var fake: FakeProvider = .{};
    const provider = fake.descriptor();
    const key = [_]u8{0x01} ** 16;
    const nonce = [_]u8{0x02} ** 12;
    const aad = &[_][]const u8{"aad"};
    const message = "secret";
    var ciphertext: [message.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try provider.aeadSeal(.aes_128_gcm, &key, &nonce, aad, message, &ciphertext, &tag);

    var in_place_success = [_]u8{ 's', 'e', 'c', 'r', 'e', 't' };
    try provider.aeadSeal(.aes_128_gcm, &key, &nonce, aad, &in_place_success, &in_place_success, &tag);
    try provider.aeadOpen(.aes_128_gcm, &key, &nonce, aad, &in_place_success, &tag, &in_place_success);
    try std.testing.expectEqualStrings(message, &in_place_success);

    fake.authentication_failure = true;
    var destination = [_]u8{0xcc} ** message.len;
    try std.testing.expectError(
        error.AuthenticationFailed,
        provider.aeadOpen(.aes_128_gcm, &key, &nonce, aad, &ciphertext, &tag, &destination),
    );
    try std.testing.expect(std.mem.allEqual(u8, &destination, 0));

    var in_place = ciphertext;
    try std.testing.expectError(
        error.AuthenticationFailed,
        provider.aeadOpen(.aes_128_gcm, &key, &nonce, aad, &in_place, &tag, &in_place),
    );
    try std.testing.expect(std.mem.allEqual(u8, &in_place, 0));

    fake.authentication_failure = false;
    fake.fail = .aead_seal;
    ciphertext = [_]u8{0xdd} ** message.len;
    tag = [_]u8{0xee} ** 16;
    try std.testing.expectError(
        error.InternalError,
        provider.aeadSeal(.aes_128_gcm, &key, &nonce, aad, message, &ciphertext, &tag),
    );
    try std.testing.expect(std.mem.allEqual(u8, &ciphertext, 0));
    try std.testing.expect(std.mem.allEqual(u8, &tag, 0));

    fake.fail = null;
    var untouched = [_]u8{0x7a} ** message.len;
    var untouched_tag = [_]u8{0x7b} ** 16;
    try std.testing.expectError(
        error.InvalidKeyLength,
        provider.aeadSeal(.aes_128_gcm, key[0..15], &nonce, aad, message, &untouched, &untouched_tag),
    );
    try std.testing.expect(std.mem.allEqual(u8, &untouched, 0x7a));
    try std.testing.expect(std.mem.allEqual(u8, &untouched_tag, 0x7b));

    var overlap_buf = [_]u8{0x41} ** 12;
    try std.testing.expectError(
        error.InvalidOverlap,
        provider.aeadSeal(
            .aes_128_gcm,
            &key,
            &nonce,
            &.{},
            overlap_buf[0..6],
            overlap_buf[1..7],
            &untouched_tag,
        ),
    );
}

test "unsupported capabilities never dispatch an operation" {
    var fake: FakeProvider = .{ .caps = .{} };
    const provider = fake.descriptor();

    var random = [_]u8{0x6a} ** 4;
    try std.testing.expectError(error.UnsupportedOperation, provider.random(&random));
    try std.testing.expect(std.mem.allEqual(u8, &random, 0x6a));
    try std.testing.expectEqual(@as(usize, 0), fake.count(.random));

    try std.testing.expectError(
        error.UnsupportedAlgorithm,
        provider.hashCreate(std.testing.allocator, .sha256),
    );
    try std.testing.expectEqual(@as(usize, 0), fake.count(.hash_create));

    const key = [_]u8{0} ** 16;
    const nonce = [_]u8{0} ** 12;
    var ciphertext: [1]u8 = .{0x55};
    var tag: [16]u8 = [_]u8{0x66} ** 16;
    try std.testing.expectError(
        error.UnsupportedAlgorithm,
        provider.aeadSeal(.aes_128_gcm, &key, &nonce, &.{}, "x", &ciphertext, &tag),
    );
    try std.testing.expectEqual(@as(usize, 0), fake.count(.aead_seal));
    try std.testing.expectError(error.UnsupportedOperation, provider.constantTimeEqual("a", "a"));
    try std.testing.expectEqual(@as(usize, 0), fake.count(.constant_time_equal));
}

test "operation errors propagate and secret outputs are wiped" {
    var fake: FakeProvider = .{ .fail = .hmac };
    const provider = fake.descriptor();
    var mac = [_]u8{0x99} ** 32;
    try std.testing.expectError(error.InternalError, provider.hmac(.sha256, "key", &.{"message"}, &mac));
    try std.testing.expect(std.mem.allEqual(u8, &mac, 0));

    fake.fail = .key_agreement_agree;
    var agreement = try provider.keyAgreementGenerate(std.testing.allocator, .x25519);
    defer agreement.deinit();
    const peer = [_]u8{0x44} ** 32;
    var shared = [_]u8{0x88} ** 32;
    try std.testing.expectError(error.InternalError, agreement.agree(&peer, &shared));
    try std.testing.expect(std.mem.allEqual(u8, &shared, 0));
}

test "signature capabilities, encodings, and errors are explicit" {
    const private_bytes = [_]u8{0x12} ** 32;
    const public_bytes = [_]u8{0x04} ++ [_]u8{0x34} ** 64;
    var fake: FakeProvider = .{};
    const provider = fake.descriptor();
    var key = try provider.signingKeyImport(std.testing.allocator, .{
        .algorithm = .ecdsa_p256,
        .encoding = .raw_secret,
        .bytes = &private_bytes,
    });
    defer key.deinit();

    var too_small: [71]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        key.sign(.ecdsa_secp256r1_sha256, &.{"message"}, &too_small),
    );
    try std.testing.expectEqual(@as(usize, 0), fake.count(.sign));

    var signature_buf: [72]u8 = undefined;
    const signature = try key.sign(.ecdsa_secp256r1_sha256, &.{"message"}, &signature_buf);
    fake.signature_invalid = true;
    try std.testing.expectError(error.SignatureInvalid, provider.verify(
        .ecdsa_secp256r1_sha256,
        .{ .algorithm = .ecdsa_p256, .encoding = .sec1_uncompressed, .bytes = &public_bytes },
        &.{"message"},
        signature,
    ));

    fake.caps.signature_verify = 0;
    try std.testing.expectError(error.UnsupportedAlgorithm, provider.verify(
        .ecdsa_secp256r1_sha256,
        .{ .algorithm = .ecdsa_p256, .encoding = .sec1_uncompressed, .bytes = &public_bytes },
        &.{"message"},
        signature,
    ));

    const sign_calls = fake.count(.sign);
    fake.caps.signature_sign = 0;
    try std.testing.expectError(
        error.UnsupportedAlgorithm,
        key.sign(.ecdsa_secp256r1_sha256, &.{"message"}, &signature_buf),
    );
    try std.testing.expectEqual(sign_calls, fake.count(.sign));
}

test "ABI and error categories are stable and explicit" {
    var fake: FakeProvider = .{};
    var provider = fake.descriptor();
    provider.abi_version += 1;
    try std.testing.expectError(error.IncompatibleAbiVersion, provider.capabilities());
    try std.testing.expectEqual(@as(usize, 0), fake.count(.capabilities));

    try std.testing.expectEqual(p.ErrorCategory.unsupported, p.errorCategory(error.UnsupportedAlgorithm));
    try std.testing.expectEqual(p.ErrorCategory.authentication, p.errorCategory(error.AuthenticationFailed));
    try std.testing.expectEqual(p.ErrorCategory.signature, p.errorCategory(error.SignatureInvalid));
    try std.testing.expectEqual(p.ErrorCategory.allocation, p.errorCategory(error.OutOfMemory));
}

test "engine secure wipe clears owned secrets" {
    var bytes = [_]u8{0xfe} ** 64;
    p.secureWipe(&bytes);
    try std.testing.expect(std.mem.allEqual(u8, &bytes, 0));

    var value: u128 = std.math.maxInt(u128);
    p.secureWipeValue(&value);
    try std.testing.expectEqual(@as(u128, 0), value);
}
