const std = @import("std");
const p = @import("provider.zig");
const state = @import("tls_state.zig");
const record = @import("record.zig");
const hello = @import("client_hello.zig");
const KeyShare = @import("key_share.zig").KeyShare;
const Standard = @import("standard.zig").StandardProvider;
const testing = std.testing;
const tls = std.crypto.tls;

test "provider transcript snapshots and clones retain independent ownership" {
    var standard = Standard.init(testing.io, testing.allocator);
    var transcript = try state.HashType(.sha256).init(standard.provider(), testing.allocator);
    defer transcript.deinit();
    try transcript.update("ab");
    var cloned = try transcript.clone(testing.allocator);
    defer cloned.deinit();
    try cloned.update("c");
    try transcript.update("z");
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("abc", &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &(try cloned.peek()));
    try testing.expect(!std.mem.eql(u8, &expected, &(try transcript.peek())));
    try testing.expectEqualSlices(u8, &(try cloned.peek()), &(try cloned.finalResult()));
}

test "provider TLS HKDF label has the exact RFC 8446 encoding" {
    var standard = Standard.init(testing.io, testing.allocator);
    const provider = standard.provider();
    const secret: [32]u8 = @splat(7);
    const actual = try state.hkdfExpandLabel(provider, state.HkdfType(.sha256), secret, "key", "", 16);
    var expected: [16]u8 = undefined;
    try provider.hkdfExpand(.sha256, &secret, &.{"\x00\x10\x09tls13 key\x00"}, &expected);
    try testing.expectEqualSlices(u8, &expected, &actual);
    try testing.expectError(error.InvalidInput, state.hkdfExpandLabel(provider, state.HkdfType(.sha256), secret, &(@as([250]u8, @splat('a'))), "", 16));
}

test "provider key shares exchange only advertised groups and clean up handles" {
    var standard = Standard.init(testing.io, testing.allocator);
    var left = try KeyShare.init(standard.provider(), testing.allocator);
    defer left.deinit();
    var right = try KeyShare.init(standard.provider(), testing.allocator);
    defer right.deinit();
    for (KeyShare.algorithms) |algorithm| {
        const group: tls.NamedGroup = @enumFromInt(@intFromEnum(algorithm));
        try left.exchange(group, right.publicKey(group).?);
        try right.exchange(group, left.publicKey(group).?);
        try testing.expectEqualSlices(u8, left.getSharedSecret().?, right.getSharedSecret().?);
    }
    try testing.expectError(error.TlsIllegalParameter, left.exchange(.x25519_ml_kem768, ""));
}

test "provider ClientHello filters capabilities and frames SNI and key-share vectors" {
    const Limited = struct {
        fn capabilities(_: *anyopaque) p.Capabilities {
            var caps = p.Capabilities.all();
            caps.aeads = 0;
            caps.setAead(.chacha20_poly1305, true);
            caps.key_agreements = 0;
            caps.setKeyAgreement(.x25519, true);
            caps.signature_verify = 0;
            caps.setVerify(.ed25519, true);
            return caps;
        }
    };
    var standard = Standard.init(testing.io, testing.allocator);
    var provider = standard.provider();
    var vtable = provider.vtable.*;
    vtable.capabilities = Limited.capabilities;
    provider.vtable = &vtable;
    var shares = try KeyShare.init(provider, testing.allocator);
    defer shares.deinit();
    try testing.expect(shares.publicKey(.secp256r1) == null);
    var buffer: [1024]u8 = undefined;
    const body = try hello.build(&buffer, try provider.capabilities(), &shares, &@as([64]u8, @splat(1)), "localhost", "");
    var decoder = tls.Decoder{ .buf = buffer[0..body.len], .their_end = body.len };
    try decoder.ensure(67);
    _ = decoder.slice(67);
    try decoder.ensure(8);
    try testing.expectEqual(@as(u16, 4), decoder.decode(u16));
    try testing.expectEqual(tls.CipherSuite.CHACHA20_POLY1305_SHA256, decoder.decode(tls.CipherSuite));
    try testing.expectEqual(tls.CipherSuite.ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, decoder.decode(tls.CipherSuite));
    try testing.expectEqualSlices(u8, &.{ 1, 0 }, decoder.slice(2));
    try decoder.ensure(2);
    var extensions = try decoder.sub(decoder.decode(u16));
    try testing.expect(decoder.eof());
    var sni_seen = false;
    var key_share_seen = false;
    while (!extensions.eof()) {
        try extensions.ensure(4);
        const kind = extensions.decode(tls.ExtensionType);
        var extension = try extensions.sub(extensions.decode(u16));
        switch (kind) {
            .server_name => {
                try testing.expectEqualSlices(u8, "\x00\x0c\x00\x00\x09localhost", extension.rest());
                sni_seen = true;
            },
            .key_share => {
                try extension.ensure(6);
                try testing.expectEqual(@as(u16, 36), extension.decode(u16));
                try testing.expectEqual(tls.NamedGroup.x25519, extension.decode(tls.NamedGroup));
                try testing.expectEqual(@as(u16, 32), extension.decode(u16));
                try testing.expectEqualSlices(u8, shares.publicKey(.x25519).?, extension.rest());
                key_share_seen = true;
            },
            .supported_versions => try testing.expectEqualSlices(u8, "\x04\x03\x04\x03\x03", extension.rest()),
            else => {},
        }
    }
    try testing.expect(sni_seen and key_share_seen);
    try testing.expectError(error.TlsRecordOverflow, hello.build(buffer[0..5], try provider.capabilities(), &shares, &@as([64]u8, @splat(1)), "localhost", ""));
}

test "provider record encodings match independent standard AEAD operations" {
    var standard = Standard.init(testing.io, testing.allocator);
    const cases = .{
        .{ tls.ProtocolVersion.tls_1_3, tls.CipherSuite.AES_128_GCM_SHA256, std.crypto.aead.aes_gcm.Aes128Gcm, 0 },
        .{ tls.ProtocolVersion.tls_1_3, tls.CipherSuite.AES_256_GCM_SHA384, std.crypto.aead.aes_gcm.Aes256Gcm, 0 },
        .{ tls.ProtocolVersion.tls_1_3, tls.CipherSuite.CHACHA20_POLY1305_SHA256, std.crypto.aead.chacha_poly.ChaCha20Poly1305, 0 },
        .{ tls.ProtocolVersion.tls_1_2, tls.CipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256, std.crypto.aead.aes_gcm.Aes128Gcm, 8 },
        .{ tls.ProtocolVersion.tls_1_2, tls.CipherSuite.ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, std.crypto.aead.aes_gcm.Aes256Gcm, 8 },
        .{ tls.ProtocolVersion.tls_1_2, tls.CipherSuite.ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, std.crypto.aead.chacha_poly.ChaCha20Poly1305, 0 },
    };
    inline for (cases) |case| {
        const version, const suite, const Aead, const explicit_iv = case;
        const plaintext = "payload";
        const key: [32]u8 = @splat(7);
        const iv: [12]u8 = @splat(9);
        const sequence: u64 = 0x0102030405060708;
        const sequence_bytes = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
        const length = plaintext.len + 16 + explicit_iv;
        const header: [5]u8 = .{ 23, 3, 3, 0, length };
        var actual: [length]u8 = undefined;
        _ = try record.seal(standard.provider(), version, suite, &actual, plaintext, &header, &key, &iv, sequence);
        var expected: [length]u8 = undefined;
        var nonce = iv;
        if (explicit_iv == 8) {
            @memcpy(expected[0..8], &sequence_bytes);
            @memcpy(nonce[4..12], &sequence_bytes);
        } else {
            for (nonce[4..], sequence_bytes) |*byte, mask| byte.* ^= mask;
        }
        const aad = if (version == .tls_1_2) sequence_bytes ++ header[0..3].* ++ [_]u8{ 0, plaintext.len } else header;
        Aead.encrypt(expected[explicit_iv..][0..plaintext.len], expected[length - 16 ..][0..16], plaintext, &aad, nonce, key[0..Aead.key_length].*);
        try testing.expectEqualSlices(u8, &expected, &actual);
        try testing.expectEqualStrings(plaintext, try record.open(standard.provider(), version, suite, &actual, &header, &key, &iv, sequence));
        actual = expected;
        actual[length - 1] ^= 1;
        try testing.expectError(error.TlsDecryptError, record.open(standard.provider(), version, suite, &actual, &header, &key, &iv, sequence));
        try testing.expect(std.mem.allEqual(u8, actual[explicit_iv..][0..plaintext.len], 0));
    }
}

test "provider record and traffic-update failures never fall back or publish partial keys" {
    const Failure = struct {
        fn seal(_: *anyopaque, _: p.AeadAlgorithm, _: []const u8, _: []const u8, _: []const []const u8, _: []const u8, _: []u8, _: []u8) p.ProviderError!void {
            return error.InternalError;
        }
        fn expand(_: *anyopaque, _: p.HashAlgorithm, _: []const u8, _: []const []const u8, _: []u8) p.ProviderError!void {
            return error.InternalError;
        }
    };
    var standard = Standard.init(testing.io, testing.allocator);
    var provider = standard.provider();
    var vtable = provider.vtable.*;
    vtable.aeadSeal = Failure.seal;
    vtable.hkdfExpand = Failure.expand;
    provider.vtable = &vtable;
    var key: [32]u8 = @splat(1);
    var iv: [12]u8 = @splat(2);
    var secret: [48]u8 = @splat(3);
    var out: [17]u8 = @splat(4);
    const header: [5]u8 = .{ 23, 3, 3, 0, 17 };
    try testing.expectError(error.InternalError, record.seal(provider, .tls_1_3, .AES_128_GCM_SHA256, &out, "x", &header, &key, &iv, 0));
    try testing.expect(std.mem.allEqual(u8, &out, 0));
    try testing.expectError(error.InternalError, record.updateTrafficKeys(provider, .AES_128_GCM_SHA256, &secret, &key, &iv));
    try testing.expect(std.mem.allEqual(u8, &key, 1));
    try testing.expect(std.mem.allEqual(u8, &iv, 2));
    try testing.expect(std.mem.allEqual(u8, &secret, 3));
}
