const std = @import("std");
const p = @import("provider.zig");
const StandardProvider = @import("standard.zig").StandardProvider;
const testing = std.testing;

fn hex(comptime value: []const u8) [value.len / 2]u8 {
    return comptime blk: {
        var out: [value.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, value) catch @compileError("invalid hex fixture");
        break :blk out;
    };
}

test "standard provider SHA transcript snapshots and independent clones" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    inline for (.{
        .{ p.HashAlgorithm.sha1, std.crypto.hash.Sha1 },
        .{ p.HashAlgorithm.sha256, std.crypto.hash.sha2.Sha256 },
        .{ p.HashAlgorithm.sha384, std.crypto.hash.sha2.Sha384 },
        .{ p.HashAlgorithm.sha512, std.crypto.hash.sha2.Sha512 },
    }) |item| {
        const algorithm = item[0];
        const Hash = item[1];
        var hash = try provider.hashCreate(testing.allocator, algorithm);
        defer hash.deinit();
        try hash.update("a");
        var clone = try hash.clone(testing.allocator);
        defer clone.deinit();
        try testing.expectError(error.OutOfMemory, hash.clone(testing.failing_allocator));
        try hash.update("bc");
        var got: [Hash.digest_length]u8 = undefined;
        var want: [Hash.digest_length]u8 = undefined;
        Hash.hash("abc", &want, .{});
        try hash.snapshot(&got);
        try testing.expectEqualSlices(u8, &want, &got);
        try hash.snapshot(&got);
        try testing.expectEqualSlices(u8, &want, &got);
        try clone.update(" different transcript");
        Hash.hash("a different transcript", &want, .{});
        try clone.snapshot(&got);
        try testing.expectEqualSlices(u8, &want, &got);
    }
}

test "standard provider HMAC and HKDF RFC 4231 and RFC 5869 known answers" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    var mac: [32]u8 = undefined;
    try provider.hmac(.sha256, &(@as([20]u8, @splat(0x0b))), &.{ "Hi ", "There" }, &mac);
    try testing.expectEqualSlices(u8, &hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), &mac);

    var prk: [32]u8 = undefined;
    try provider.hkdfExtract(.sha256, &hex("000102030405060708090a0b0c"), &.{ &(@as([11]u8, @splat(0x0b))), &(@as([11]u8, @splat(0x0b))) }, &prk);
    try testing.expectEqualSlices(u8, &hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), &prk);
    var okm: [42]u8 = undefined;
    try provider.hkdfExpand(.sha256, &prk, &.{ &hex("f0f1f2f3f4"), &hex("f5f6f7f8f9") }, &okm);
    try testing.expectEqualSlices(u8, &hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), &okm);
}

test "standard provider HMAC HKDF and PRF all hash variants" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    inline for (.{
        .{ p.HashAlgorithm.sha1, std.crypto.hash.Sha1 },
        .{ p.HashAlgorithm.sha256, std.crypto.hash.sha2.Sha256 },
        .{ p.HashAlgorithm.sha384, std.crypto.hash.sha2.Sha384 },
        .{ p.HashAlgorithm.sha512, std.crypto.hash.sha2.Sha512 },
    }) |item| {
        const algorithm = item[0];
        const Hmac = std.crypto.auth.hmac.Hmac(item[1]);
        const Hkdf = std.crypto.kdf.hkdf.Hkdf(Hmac);
        var mac: [Hmac.mac_length]u8 = undefined;
        var expected_mac: [Hmac.mac_length]u8 = undefined;
        try provider.hmac(algorithm, "key", &.{ "hello", "", " world" }, &mac);
        Hmac.create(&expected_mac, "hello world", "key");
        try testing.expectEqualSlices(u8, &expected_mac, &mac);
        try provider.hkdfExtract(algorithm, "salt", &.{ "hello", " world" }, &mac);
        const expected_prk = Hkdf.extract("salt", "hello world");
        try testing.expectEqualSlices(u8, &expected_prk, &mac);
        var expanded: [131]u8 = undefined;
        var expected_expanded: [131]u8 = undefined;
        try provider.hkdfExpand(algorithm, &mac, &.{ "info", "", " suffix" }, &expanded);
        Hkdf.expand(&expected_expanded, "info suffix", expected_prk);
        try testing.expectEqualSlices(u8, &expected_expanded, &expanded);
        try provider.hkdfExpand(algorithm, &mac, &.{}, &.{});
        try provider.tls12Prf(algorithm, "secret", "label", &.{ "see", "d" }, &expanded);
        expected_expanded = std.crypto.tls.hmacExpandLabel(Hmac, "secret", &.{ "label", "seed" }, expected_expanded.len);
        try testing.expectEqualSlices(u8, &expected_expanded, &expanded);
    }
}

test "standard provider AES GCM NIST known answer" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    var ciphertext: [16]u8 = undefined;
    var tag: [16]u8 = undefined;
    try provider.aeadSeal(.aes_128_gcm, &(@as([16]u8, @splat(0))), &(@as([12]u8, @splat(0))), &.{}, &(@as([16]u8, @splat(0))), &ciphertext, &tag);
    try testing.expectEqualSlices(u8, &hex("0388dace60b6a392f328c2b971b2fe78"), &ciphertext);
    try testing.expectEqualSlices(u8, &hex("ab6e47d42cec13bdf53a67b21257bddf"), &tag);
}

test "standard provider AEAD multipart AAD in place and authentication failure wiping" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    inline for (.{
        .{ p.AeadAlgorithm.aes_128_gcm, std.crypto.aead.aes_gcm.Aes128Gcm },
        .{ p.AeadAlgorithm.aes_256_gcm, std.crypto.aead.aes_gcm.Aes256Gcm },
        .{ p.AeadAlgorithm.chacha20_poly1305, std.crypto.aead.chacha_poly.ChaCha20Poly1305 },
    }) |item| {
        const algorithm = item[0];
        const Aead = item[1];
        const key: [Aead.key_length]u8 = @splat(0x51);
        const nonce: [12]u8 = @splat(0x42);
        const message = "record protection test";
        var ciphertext: [message.len]u8 = undefined;
        var reference: [message.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        var reference_tag: [16]u8 = undefined;
        try provider.aeadSeal(algorithm, &key, &nonce, &.{ "aa", "", "d" }, message, &ciphertext, &tag);
        Aead.encrypt(&reference, &reference_tag, message, "aad", nonce, key);
        try testing.expectEqualSlices(u8, &reference, &ciphertext);
        try testing.expectEqualSlices(u8, &reference_tag, &tag);
        try provider.aeadOpen(algorithm, &key, &nonce, &.{"aad"}, &ciphertext, &tag, &ciphertext);
        try testing.expectEqualStrings(message, &ciphertext);
        try provider.aeadSeal(algorithm, &key, &nonce, &.{"aad"}, &ciphertext, &ciphertext, &tag);
        try testing.expectEqualSlices(u8, &reference, &ciphertext);
        tag[0] ^= 1;
        try testing.expectError(error.AuthenticationFailed, provider.aeadOpen(algorithm, &key, &nonce, &.{"aad"}, &ciphertext, &tag, &ciphertext));
        try testing.expect(std.mem.allEqual(u8, &ciphertext, 0));
    }
}

test "standard provider key agreements agree and reject invalid peers" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    inline for (.{ p.KeyAgreementAlgorithm.x25519, p.KeyAgreementAlgorithm.secp256r1, p.KeyAgreementAlgorithm.secp384r1 }) |algorithm| {
        var alice = try provider.keyAgreementGenerate(testing.allocator, algorithm);
        defer alice.deinit();
        var bob = try provider.keyAgreementGenerate(testing.allocator, algorithm);
        defer bob.deinit();
        var alice_public: [algorithm.publicKeyLength()]u8 = undefined;
        var bob_public: [algorithm.publicKeyLength()]u8 = undefined;
        var alice_secret: [algorithm.sharedSecretLength()]u8 = undefined;
        var bob_secret: [algorithm.sharedSecretLength()]u8 = undefined;
        try alice.publicKey(&alice_public);
        try bob.publicKey(&bob_public);
        try alice.agree(&bob_public, &alice_secret);
        try bob.agree(&alice_public, &bob_secret);
        try testing.expectEqualSlices(u8, &alice_secret, &bob_secret);
        try testing.expect(!std.mem.allEqual(u8, &alice_secret, 0));
        @memset(&bob_public, 0);
        if (algorithm != .x25519) bob_public[0] = 4;
        try testing.expectError(error.KeyAgreementFailed, alice.agree(&bob_public, &alice_secret));
        try testing.expect(std.mem.allEqual(u8, &alice_secret, 0));
    }
}

test "standard provider ML KEM encapsulates and uses implicit rejection" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    var key = try provider.kemGenerate(testing.allocator, .ml_kem_768);
    defer key.deinit();
    var public: [1184]u8 = undefined;
    var ciphertext: [1088]u8 = undefined;
    var sender_secret: [32]u8 = undefined;
    var receiver_secret: [32]u8 = undefined;
    try key.publicKey(&public);
    try provider.kemEncapsulate(.ml_kem_768, &public, &ciphertext, &sender_secret);
    try key.decapsulate(&ciphertext, &receiver_secret);
    try testing.expectEqualSlices(u8, &sender_secret, &receiver_secret);
    ciphertext[0] ^= 1;
    try key.decapsulate(&ciphertext, &receiver_secret);
    try testing.expect(!std.mem.eql(u8, &sender_secret, &receiver_secret));
    @memset(&public, 0xff);
    try testing.expectError(error.EncapsulationFailed, provider.kemEncapsulate(.ml_kem_768, &public, &ciphertext, &sender_secret));
    try testing.expect(std.mem.allEqual(u8, &ciphertext, 0));
    try testing.expect(std.mem.allEqual(u8, &sender_secret, 0));
}

test "standard provider ECDSA and Ed25519 sign verify and reject wrong messages" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    inline for (.{
        .{ p.SignatureScheme.ecdsa_secp256r1_sha256, std.crypto.sign.ecdsa.EcdsaP256Sha256 },
        .{ p.SignatureScheme.ecdsa_secp384r1_sha384, std.crypto.sign.ecdsa.EcdsaP384Sha384 },
        .{ p.SignatureScheme.ed25519, std.crypto.sign.Ed25519 },
    }) |item| {
        const scheme = item[0];
        const Scheme = item[1];
        const key_pair = try Scheme.KeyPair.generateDeterministic(@splat(0x42));
        const secret = if (scheme == .ed25519) key_pair.secret_key.seed() else key_pair.secret_key.toBytes();
        var key = try provider.signingKeyImport(testing.allocator, .{ .algorithm = scheme.keyAlgorithm(), .encoding = .raw_secret, .bytes = &secret });
        defer key.deinit();
        const bytes = if (scheme == .ed25519) key_pair.public_key.toBytes() else key_pair.public_key.toUncompressedSec1();
        const public_key: p.PublicKey = .{
            .algorithm = scheme.keyAlgorithm(),
            .encoding = if (scheme == .ed25519) .ed25519_raw else .sec1_uncompressed,
            .bytes = &bytes,
        };
        var signature: [scheme.signatureCapacity().?]u8 = undefined;
        const encoded = try key.sign(scheme, &.{ "hello", "", " world" }, &signature);
        try provider.verify(scheme, public_key, &.{"hello world"}, encoded);
        try testing.expectError(error.SignatureInvalid, provider.verify(scheme, public_key, &.{"different message"}, encoded));
        try testing.expectError(error.OutputTooSmall, key.sign(scheme, &.{"hello world"}, signature[0..1]));
    }
}

test "standard provider rejects invalid private scalars and unsupported RSA signing" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    const caps = try provider.capabilities();
    try testing.expect(caps.supportsVerify(.rsa_pss_rsae_sha256));
    try testing.expect(!caps.supportsSign(.rsa_pss_rsae_sha256));
    try testing.expectError(error.UnsupportedAlgorithm, provider.signingKeyImport(testing.allocator, .{ .algorithm = .rsa, .encoding = .rsa_pkcs1_der, .bytes = "\x30\x00" }));
    try testing.expectError(error.InvalidEncoding, provider.signingKeyImport(testing.allocator, .{ .algorithm = .ecdsa_p256, .encoding = .sec1_der, .bytes = "\x30\x00" }));
    inline for (.{ p.SignatureKeyAlgorithm.ecdsa_p256, p.SignatureKeyAlgorithm.ecdsa_p384 }) |algorithm| {
        const length = if (algorithm == .ecdsa_p256) 32 else 48;
        try testing.expectError(error.InvalidEncoding, provider.signingKeyImport(testing.allocator, .{ .algorithm = algorithm, .encoding = .raw_secret, .bytes = &(@as([length]u8, @splat(0))) }));
        try testing.expectError(error.InvalidEncoding, provider.signingKeyImport(testing.allocator, .{ .algorithm = algorithm, .encoding = .raw_secret, .bytes = &(@as([length]u8, @splat(0xff))) }));
    }
}

test "standard provider constant time comparison spans fixed blocks" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    var a: [97]u8 = @splat(0x51);
    var b = a;
    for (0..a.len + 1) |length| try testing.expect(try provider.constantTimeEqual(a[0..length], b[0..length]));
    for (0..a.len) |i| {
        b[i] ^= 1;
        try testing.expect(!try provider.constantTimeEqual(&a, &b));
        b[i] ^= 1;
    }
}

test "standard provider allocation failure leaves handles and AEAD outputs clean" {
    var owner = StandardProvider.init(testing.io, testing.failing_allocator);
    const provider = owner.provider();
    try testing.expectError(error.OutOfMemory, provider.hashCreate(testing.failing_allocator, .sha256));
    try testing.expectError(error.OutOfMemory, provider.keyAgreementGenerate(testing.failing_allocator, .x25519));
    try testing.expectError(error.OutOfMemory, provider.kemGenerate(testing.failing_allocator, .ml_kem_768));
    try testing.expectError(error.OutOfMemory, provider.signingKeyImport(testing.failing_allocator, .{
        .algorithm = .ed25519,
        .encoding = .raw_secret,
        .bytes = &(@as([32]u8, @splat(0))),
    }));
    var ciphertext: [3]u8 = @splat(0x55);
    var tag: [16]u8 = @splat(0x55);
    try testing.expectError(error.OutOfMemory, provider.aeadSeal(.aes_128_gcm, &(@as([16]u8, @splat(0))), &(@as([12]u8, @splat(0))), &.{ "a", "b" }, "abc", &ciphertext, &tag));
    try testing.expect(std.mem.allEqual(u8, &ciphertext, 0));
    try testing.expect(std.mem.allEqual(u8, &tag, 0));
}

test "standard provider entropy failures are explicit without fallback" {
    const Fail = struct {
        fn randomSecure(_: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
            @memset(buffer, 0x55);
            return error.EntropyUnavailable;
        }
        fn insecureFallback(_: ?*anyopaque, _: []u8) void {
            @panic("randomSecure failure must never fall back to random");
        }
    };
    var io_vtable = testing.io.vtable.*;
    io_vtable.randomSecure = Fail.randomSecure;
    io_vtable.random = Fail.insecureFallback;
    var owner = StandardProvider.init(.{ .userdata = null, .vtable = &io_vtable }, testing.allocator);
    const provider = owner.provider();
    var bytes: [32]u8 = @splat(0x55);
    try testing.expectError(error.EntropyUnavailable, provider.random(&bytes));
    try testing.expect(std.mem.allEqual(u8, &bytes, 0));
    inline for (.{ p.KeyAgreementAlgorithm.x25519, p.KeyAgreementAlgorithm.secp256r1, p.KeyAgreementAlgorithm.secp384r1 }) |algorithm| {
        try testing.expectError(error.EntropyUnavailable, provider.keyAgreementGenerate(testing.allocator, algorithm));
    }
    try testing.expectError(error.EntropyUnavailable, provider.kemGenerate(testing.allocator, .ml_kem_768));
    var key = try provider.signingKeyImport(testing.allocator, .{ .algorithm = .ed25519, .encoding = .raw_secret, .bytes = &bytes });
    defer key.deinit();
    var signature: [64]u8 = @splat(0x55);
    try testing.expectError(error.EntropyUnavailable, key.sign(.ed25519, &.{"message"}, &signature));
    try testing.expect(std.mem.allEqual(u8, &signature, 0));
}

test "standard provider RSA verification bounds key and signature encodings" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    const signature: [256]u8 = @splat(0);
    for ([_][]const u8{ "\x30", "\x30\x00", "\x30\x82\x10\x00", "\x30\x06\x02\x01\x80\x02\x01\x03" }) |bytes| {
        try testing.expectError(error.InvalidEncoding, provider.verify(.rsa_pkcs1_sha256, .{ .algorithm = .rsa, .encoding = .rsa_pkcs1_der, .bytes = bytes }, &.{"message"}, &signature));
    }
}

fn base64Url(comptime length: usize, value: []const u8) ![length]u8 {
    var bytes: [length]u8 = undefined;
    try testing.expectEqual(length, try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(value));
    try std.base64.url_safe_no_pad.Decoder.decode(&bytes, value);
    return bytes;
}

test "standard provider RSA PKCS1 SHA256 RFC 7515 A.2 known answer" {
    const modulus = try base64Url(256, "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" ++
        "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" ++
        "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" ++
        "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" ++
        "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" ++
        "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ");
    const signed = try base64Url(256, "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" ++
        "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" ++
        "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" ++
        "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" ++
        "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" ++
        "p0igcN_IoypGlUPQGe77Rw");
    const encoded_key = "\x30\x82\x01\x0a\x02\x82\x01\x01\x00".* ++ modulus ++ "\x02\x03\x01\x00\x01".*;
    const header = "{\"alg\":\"RS256\"}";
    var header_bytes: [std.base64.url_safe_no_pad.Encoder.calcSize(header.len)]u8 = undefined;
    const header_encoded = std.base64.url_safe_no_pad.Encoder.encode(&header_bytes, header);
    const parts = [_][]const u8{
        header_encoded,
        ".",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" ++
            "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    };
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    const key: p.PublicKey = .{ .algorithm = .rsa, .encoding = .rsa_pkcs1_der, .bytes = &encoded_key };
    try provider.verify(.rsa_pkcs1_sha256, key, &parts, &signed);
    try testing.expectError(error.SignatureInvalid, provider.verify(.rsa_pkcs1_sha256, key, &.{"wrong message"}, &signed));
    try testing.expectError(error.InvalidSignatureLength, provider.verify(.rsa_pkcs1_sha256, key, &parts, signed[0..255]));
    try testing.expectError(error.SignatureInvalid, provider.verify(.rsa_pss_rsae_sha256, key, &parts, &signed));
}

test "standard provider RSA PSS SHA384 RFC 7520 section 4.2 known answer" {
    const modulus = try base64Url(256, "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" ++
        "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" ++
        "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" ++
        "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" ++
        "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" ++
        "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" ++
        "HdrNP5zw");
    const signed = try base64Url(256, "cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2I" ++
        "pN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXU" ++
        "vdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRX" ++
        "e8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT" ++
        "0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a" ++
        "6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw");
    const encoded_key = "\x30\x82\x01\x0a\x02\x82\x01\x01\x00".* ++ modulus ++ "\x02\x03\x01\x00\x01".*;
    const header = "{\"alg\":\"PS384\",\"kid\":\"bilbo.baggins@hobbiton.example\"}";
    var header_bytes: [std.base64.url_safe_no_pad.Encoder.calcSize(header.len)]u8 = undefined;
    const header_encoded = std.base64.url_safe_no_pad.Encoder.encode(&header_bytes, header);
    const parts = [_][]const u8{
        header_encoded,
        ".",
        "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" ++
            "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" ++
            "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" ++
            "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4",
    };
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    const key: p.PublicKey = .{ .algorithm = .rsa, .encoding = .rsa_pkcs1_der, .bytes = &encoded_key };
    try provider.verify(.rsa_pss_rsae_sha384, key, &parts, &signed);
    try testing.expectError(error.SignatureInvalid, provider.verify(.rsa_pss_rsae_sha384, key, &.{"wrong message"}, &signed));
    try testing.expectError(error.SignatureInvalid, provider.verify(.rsa_pss_rsae_sha256, key, &parts, &signed));
}

fn derElement(comptime tag: u8, bytes: anytype) [bytes.len + (if (bytes.len < 128) @as(usize, 2) else 3)]u8 {
    if (bytes.len > 255) @compileError("fixture element too large");
    const header_len: usize = if (bytes.len < 128) 2 else 3;
    var encoded: [header_len + bytes.len]u8 = undefined;
    encoded[0] = tag;
    if (header_len == 2) {
        encoded[1] = @intCast(bytes.len);
    } else {
        encoded[1] = 0x81;
        encoded[2] = @intCast(bytes.len);
    }
    @memcpy(encoded[header_len..], &bytes);
    return encoded;
}

test "standard provider imports SEC1 and PKCS8 ECDSA keys with matching public points" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    inline for (.{
        .{ p.SignatureScheme.ecdsa_secp256r1_sha256, std.crypto.sign.ecdsa.EcdsaP256Sha256 },
        .{ p.SignatureScheme.ecdsa_secp384r1_sha384, std.crypto.sign.ecdsa.EcdsaP384Sha384 },
    }) |item| {
        const scheme = item[0];
        const Scheme = item[1];
        const pair = try Scheme.KeyPair.generateDeterministic(@splat(0x39));
        const secret = pair.secret_key.toBytes();
        const public = pair.public_key.toUncompressedSec1();
        const curve = if (scheme == .ecdsa_secp256r1_sha256)
            derElement(6, "\x2a\x86\x48\xce\x3d\x03\x01\x07".*)
        else
            derElement(6, "\x2b\x81\x04\x00\x22".*);
        const algorithm = derElement(0x30, derElement(6, "\x2a\x86\x48\xce\x3d\x02\x01".*) ++ curve);
        const sec1 = derElement(0x30, "\x02\x01\x01".* ++ derElement(4, secret) ++
            derElement(0xa0, curve) ++ derElement(0xa1, derElement(3, [_]u8{0} ++ public)));
        const compressed_sec1 = derElement(0x30, "\x02\x01\x01".* ++ derElement(4, secret) ++
            derElement(0xa1, derElement(3, [_]u8{0} ++ pair.public_key.toCompressedSec1())));
        const pkcs8 = derElement(0x30, "\x02\x01\x00".* ++ algorithm ++ derElement(4, sec1));
        inline for (.{
            .{ p.PrivateKeyEncoding.sec1_der, sec1 },
            .{ p.PrivateKeyEncoding.sec1_der, compressed_sec1 },
            .{ p.PrivateKeyEncoding.pkcs8_der, pkcs8 },
        }) |encoded| {
            var container = encoded[1];
            var key = try provider.signingKeyImport(testing.allocator, .{
                .algorithm = scheme.keyAlgorithm(),
                .encoding = encoded[0],
                .bytes = &container,
            });
            defer key.deinit();
            @memset(&container, 0);
            var signature: [scheme.signatureCapacity().?]u8 = undefined;
            const signed = try key.sign(scheme, &.{"imported key"}, &signature);
            try provider.verify(scheme, .{
                .algorithm = scheme.keyAlgorithm(),
                .encoding = .sec1_uncompressed,
                .bytes = &public,
            }, &.{"imported key"}, signed);
        }
        var wrong_public = public;
        wrong_public[wrong_public.len - 1] ^= 1;
        const inconsistent = derElement(0x30, "\x02\x01\x01".* ++ derElement(4, secret) ++
            derElement(0xa1, derElement(3, [_]u8{0} ++ wrong_public)));
        try testing.expectError(error.InvalidEncoding, provider.signingKeyImport(testing.allocator, .{
            .algorithm = scheme.keyAlgorithm(),
            .encoding = .sec1_der,
            .bytes = &inconsistent,
        }));
        for (0..pkcs8.len) |length| {
            try testing.expectError(error.InvalidEncoding, provider.signingKeyImport(testing.allocator, .{
                .algorithm = scheme.keyAlgorithm(),
                .encoding = .pkcs8_der,
                .bytes = pkcs8[0..length],
            }));
        }
    }
}

test "standard provider imports RFC 8410 Ed25519 PKCS8 and RFC 5958 public keys" {
    var owner = StandardProvider.init(testing.io, testing.allocator);
    const provider = owner.provider();
    const seed: [32]u8 = @splat(0x37);
    const pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const public = pair.public_key.toBytes();
    const algorithm = derElement(0x30, derElement(6, "\x2b\x65\x70".*));
    const private = derElement(4, derElement(4, seed));
    const version0 = derElement(0x30, "\x02\x01\x00".* ++ algorithm ++ private);
    const version1 = derElement(0x30, "\x02\x01\x01".* ++ algorithm ++ private ++
        derElement(0x81, [_]u8{0} ++ public));
    inline for (.{ version0, version1 }) |bytes| {
        var key = try provider.signingKeyImport(testing.allocator, .{
            .algorithm = .ed25519,
            .encoding = .pkcs8_der,
            .bytes = &bytes,
        });
        defer key.deinit();
        var signature: [64]u8 = undefined;
        const signed = try key.sign(.ed25519, &.{"PKCS8"}, &signature);
        try provider.verify(.ed25519, .{ .algorithm = .ed25519, .encoding = .ed25519_raw, .bytes = &public }, &.{"PKCS8"}, signed);
    }
    var wrong_public = version1;
    wrong_public[wrong_public.len - 1] ^= 1;
    const missing_public = derElement(0x30, "\x02\x01\x01".* ++ algorithm ++ private);
    const bad_parameters = derElement(0x30, "\x02\x01\x00".* ++
        derElement(0x30, derElement(6, "\x2b\x65\x70".*) ++ "\x05\x00".*) ++ private);
    inline for (.{ wrong_public, missing_public, bad_parameters }) |bytes| {
        try testing.expectError(error.InvalidEncoding, provider.signingKeyImport(testing.allocator, .{
            .algorithm = .ed25519,
            .encoding = .pkcs8_der,
            .bytes = &bytes,
        }));
    }
    const attributes = derElement(0x30, "\x02\x01\x00".* ++ algorithm ++ private ++ "\xa0\x00".*);
    try testing.expectError(error.UnsupportedOperation, provider.signingKeyImport(testing.allocator, .{
        .algorithm = .ed25519,
        .encoding = .pkcs8_der,
        .bytes = &attributes,
    }));
}
