const builtin = @import("builtin");
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = std.crypto;
const tls = std.crypto.tls;

const Socket = @import("../net/socket.zig").Socket;
const SocketIoReader = @import("../net/socket.zig").SocketIoReader;
const SocketIoWriter = @import("../net/socket.zig").SocketIoWriter;
const alpn = @import("alpn.zig");
const errors = @import("errors.zig");
const TlsClient = @import("client.zig");
const any_io = @import("../io/any_io.zig");
const IoContext = @import("../io/context.zig").IoContext;

pub const trust = @import("trust.zig");
pub const cert_signature = @import("cert_signature.zig");
pub const TrustProvider = trust.TrustProvider;
pub const VerifyPeerRequest = trust.VerifyPeerRequest;
pub const PeerRole = trust.PeerRole;
pub const PeerIdentity = trust.PeerIdentity;
pub const IpAddress = trust.IpAddress;
pub const TrustLimits = trust.TrustLimits;
pub const CaBundleSource = trust.CaBundleSource;
pub const TrustSource = trust.TrustSource;
pub const ServerAuthentication = trust.ServerAuthentication;
pub const CertificateSignatureAlgorithmIdentifier = cert_signature.AlgorithmIdentifier;
pub const CertificateSignatureVerifier = cert_signature.CertificateSignatureVerifier;
pub const VerifyCertificateSignatureRequest = cert_signature.VerifyCertificateSignatureRequest;
pub const CertificateSignatureError = cert_signature.CertificateSignatureError;
pub const TrustError = errors.TrustError;
pub const crypto_provider = @import("crypto/provider.zig");
pub const CryptoProvider = crypto_provider.CryptoProvider;
pub const CryptoProviderVTable = crypto_provider.VTable;
pub const CryptoProviderCapabilities = crypto_provider.Capabilities;
pub const CryptoCapabilities = crypto_provider.Capabilities;
pub const CryptoProviderError = crypto_provider.ProviderError;

pub const server = @import("server.zig");
pub const acceptServer = server.acceptServer;

pub const record_header_len = 5;
const max_plaintext_len = 1 << 14;
const max_ciphertext_len = max_plaintext_len + 256;
const max_record_len = record_header_len + max_ciphertext_len;
const max_new_session_ticket_body_len = 4 + 4 + 1 + std.math.maxInt(u8) +
    2 + std.math.maxInt(u16) + 2 + std.math.maxInt(u16);
const max_post_handshake_buffer_len = 4 + max_new_session_ticket_body_len;
// Bound work per read when a peer floods control or zero-length application records.
const max_skipped_records_per_read = 32;

const ContentType = tls.ContentType;

const RecordHeader = struct {
    content_type: ContentType,
    version: tls.ProtocolVersion,
    length: u16,

    fn format(self: RecordHeader, buf: *[record_header_len]u8) void {
        buf[0] = @intFromEnum(self.content_type);
        buf[1] = 0x03;
        buf[2] = 0x03;
        mem.writeInt(u16, buf[3..5], self.length, .big);
    }

    fn parse(buf: *[record_header_len]u8) RecordHeader {
        return .{
            .content_type = @enumFromInt(buf[0]),
            .version = .tls_1_2,
            .length = mem.readInt(u16, buf[3..5], .big),
        };
    }
};

pub fn nonceTLS13(iv: *const [12]u8, seq: u64) [12]u8 {
    var nonce: [12]u8 = iv.*;
    var seq_bytes: [8]u8 = undefined;
    mem.writeInt(u64, &seq_bytes, seq, .big);
    for (0..8) |i| {
        nonce[4 + i] = nonce[4 + i] ^ seq_bytes[i];
    }
    return nonce;
}

pub fn encryptTLS13(
    comptime Aead: type,
    out: []u8,
    plaintext: []const u8,
    record_header: *const [record_header_len]u8,
    nonce: *const [12]u8,
    key: *const [Aead.key_length]u8,
) ![]u8 {
    var tag: [Aead.tag_length]u8 = undefined;
    Aead.encrypt(out[0..plaintext.len], &tag, plaintext, &record_header.*, nonce.*, key.*);
    @memcpy(out[plaintext.len..][0..Aead.tag_length], &tag);
    return out[0 .. plaintext.len + Aead.tag_length];
}

pub fn decryptTLS13(
    comptime Aead: type,
    ciphertext: []u8,
    record_header: *const [record_header_len]u8,
    nonce: *const [12]u8,
    key: *const [Aead.key_length]u8,
) ![]u8 {
    if (ciphertext.len < Aead.tag_length) return error.TlsDecryptError;
    const tag: [Aead.tag_length]u8 = ciphertext[ciphertext.len - Aead.tag_length ..][0..Aead.tag_length].*;
    const ct_len = ciphertext.len - Aead.tag_length;
    Aead.decrypt(ciphertext[0..ct_len], ciphertext[0..ct_len], tag, &record_header.*, nonce.*, key.*) catch return error.TlsDecryptError;
    return ciphertext[0..ct_len];
}

fn encryptTLS12Aead(
    comptime Aead: type,
    comptime record_iv_length: usize,
    out: []u8,
    plaintext: []const u8,
    hdr: *const [record_header_len]u8,
    seq: u64,
    iv: *const [12]u8,
    key: *const [Aead.key_length]u8,
) ![]u8 {
    const fixed_iv_length = Aead.nonce_length - record_iv_length;
    comptime std.debug.assert(record_iv_length == 0 or record_iv_length == 8);

    var nonce: [12]u8 = undefined;
    if (record_iv_length == 0) {
        nonce = iv.*;
        var seq_bytes: [8]u8 = undefined;
        mem.writeInt(u64, &seq_bytes, seq, .big);
        for (seq_bytes, 0..) |byte, i| {
            nonce[fixed_iv_length - 8 + i] ^= byte;
        }
    } else {
        @memcpy(nonce[0..fixed_iv_length], iv[0..fixed_iv_length]);
        mem.writeInt(u64, nonce[fixed_iv_length..][0..8], seq, .big);
        @memcpy(out[0..record_iv_length], nonce[fixed_iv_length..]);
    }

    var aad: [record_header_len + 8]u8 = undefined;
    mem.writeInt(u64, aad[0..8], seq, .big);
    aad[8] = hdr[0];
    aad[9] = hdr[1];
    aad[10] = hdr[2];
    mem.writeInt(u16, aad[11..13], @intCast(plaintext.len), .big);

    var tag: [Aead.tag_length]u8 = undefined;
    const ciphertext = out[record_iv_length..][0..plaintext.len];
    Aead.encrypt(ciphertext, &tag, plaintext, &aad, nonce, key.*);
    @memcpy(out[record_iv_length + plaintext.len ..][0..Aead.tag_length], &tag);
    return out[0 .. record_iv_length + plaintext.len + Aead.tag_length];
}

fn decryptTLS12Aead(
    comptime Aead: type,
    comptime record_iv_length: usize,
    ciphertext: []u8,
    hdr: *const [record_header_len]u8,
    seq: u64,
    iv: *const [12]u8,
    key: *const [Aead.key_length]u8,
) ![]u8 {
    const fixed_iv_length = Aead.nonce_length - record_iv_length;
    comptime std.debug.assert(record_iv_length == 0 or record_iv_length == 8);
    if (ciphertext.len < record_iv_length + Aead.tag_length) return error.TlsDecryptError;

    var nonce: [12]u8 = undefined;
    if (record_iv_length == 0) {
        nonce = iv.*;
        var seq_bytes: [8]u8 = undefined;
        mem.writeInt(u64, &seq_bytes, seq, .big);
        for (seq_bytes, 0..) |byte, i| {
            nonce[fixed_iv_length - 8 + i] ^= byte;
        }
    } else {
        @memcpy(nonce[0..fixed_iv_length], iv[0..fixed_iv_length]);
        @memcpy(nonce[fixed_iv_length..], ciphertext[0..record_iv_length]);
    }

    const plain_len = ciphertext.len - record_iv_length - Aead.tag_length;
    var aad: [record_header_len + 8]u8 = undefined;
    mem.writeInt(u64, aad[0..8], seq, .big);
    aad[8] = hdr[0];
    aad[9] = hdr[1];
    aad[10] = hdr[2];
    mem.writeInt(u16, aad[11..13], @intCast(plain_len), .big);
    const tag: [Aead.tag_length]u8 = ciphertext[ciphertext.len - Aead.tag_length ..][0..Aead.tag_length].*;
    const encrypted = ciphertext[record_iv_length..][0..plain_len];
    Aead.decrypt(encrypted, encrypted, tag, &aad, nonce, key.*) catch return error.TlsDecryptError;
    return encrypted;
}

/// RFC 5288 AES-GCM TLS 1.2 record protection.
///
/// Wire layout: explicit_nonce(8) || ciphertext || tag(16).
pub fn encryptTLS12(
    comptime Aead: type,
    out: []u8,
    plaintext: []const u8,
    hdr: *const [record_header_len]u8,
    seq: u64,
    iv: *const [12]u8,
    key: *const [Aead.key_length]u8,
) ![]u8 {
    return encryptTLS12Aead(Aead, 8, out, plaintext, hdr, seq, iv, key);
}

pub fn decryptTLS12(
    comptime Aead: type,
    ciphertext: []u8,
    hdr: *const [record_header_len]u8,
    seq: u64,
    iv: *const [12]u8,
    key: *const [Aead.key_length]u8,
) ![]u8 {
    return decryptTLS12Aead(Aead, 8, ciphertext, hdr, seq, iv, key);
}

fn tls12CiphertextLen(cipher_suite: tls.CipherSuite, plaintext_len: usize) !usize {
    return plaintext_len + switch (cipher_suite) {
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        => @as(usize, 8 + crypto.aead.aes_gcm.Aes128Gcm.tag_length),
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        => @as(usize, crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length),
        else => return error.TlsUnsupportedCipherSuite,
    };
}

fn encryptTLS12ForSuite(
    out: []u8,
    plaintext: []const u8,
    hdr: *const [record_header_len]u8,
    seq: u64,
    iv: *const [12]u8,
    key: *const [32]u8,
    cipher_suite: tls.CipherSuite,
) ![]u8 {
    return switch (cipher_suite) {
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, .ECDHE_RSA_WITH_AES_128_GCM_SHA256 => blk: {
            var k: [16]u8 = undefined;
            @memcpy(&k, key[0..16]);
            break :blk try encryptTLS12(crypto.aead.aes_gcm.Aes128Gcm, out, plaintext, hdr, seq, iv, &k);
        },
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, .ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            return encryptTLS12(crypto.aead.aes_gcm.Aes256Gcm, out, plaintext, hdr, seq, iv, key);
        },
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            return encryptTLS12Aead(crypto.aead.chacha_poly.ChaCha20Poly1305, 0, out, plaintext, hdr, seq, iv, key);
        },
        else => error.TlsUnsupportedCipherSuite,
    };
}

fn decryptTLS12ForSuite(
    ciphertext: []u8,
    hdr: *const [record_header_len]u8,
    seq: u64,
    iv: *const [12]u8,
    key: *const [32]u8,
    cipher_suite: tls.CipherSuite,
) ![]u8 {
    return switch (cipher_suite) {
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, .ECDHE_RSA_WITH_AES_128_GCM_SHA256 => blk: {
            var k: [16]u8 = undefined;
            @memcpy(&k, key[0..16]);
            break :blk try decryptTLS12(crypto.aead.aes_gcm.Aes128Gcm, ciphertext, hdr, seq, iv, &k);
        },
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, .ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            return decryptTLS12(crypto.aead.aes_gcm.Aes256Gcm, ciphertext, hdr, seq, iv, key);
        },
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            return decryptTLS12Aead(crypto.aead.chacha_poly.ChaCha20Poly1305, 0, ciphertext, hdr, seq, iv, key);
        },
        else => error.TlsUnsupportedCipherSuite,
    };
}

fn decryptTLS13ForSuite(
    ciphertext: []u8,
    hdr: *const [record_header_len]u8,
    seq: u64,
    iv: *const [12]u8,
    key: *const [32]u8,
    cipher_suite: tls.CipherSuite,
) ![]u8 {
    const nonce = nonceTLS13(iv, seq);
    return switch (cipher_suite) {
        .AES_128_GCM_SHA256 => blk: {
            var k: [16]u8 = undefined;
            @memcpy(&k, key[0..16]);
            break :blk try decryptTLS13(crypto.aead.aes_gcm.Aes128Gcm, ciphertext, hdr, &nonce, &k);
        },
        .AES_256_GCM_SHA384 => {
            return decryptTLS13(crypto.aead.aes_gcm.Aes256Gcm, ciphertext, hdr, &nonce, key);
        },
        .CHACHA20_POLY1305_SHA256 => {
            return decryptTLS13(crypto.aead.chacha_poly.ChaCha20Poly1305, ciphertext, hdr, &nonce, key);
        },
        else => error.TlsUnsupportedCipherSuite,
    };
}

fn writeBoundedEncryptedRecord(
    sender: anytype,
    version: tls.ProtocolVersion,
    key: [32]u8,
    iv: [12]u8,
    cipher_suite: tls.CipherSuite,
    seq: *u64,
    data: []const u8,
    content_type: ContentType,
) !usize {
    const plaintext_len = @min(data.len, max_plaintext_len);
    if (plaintext_len == 0) return 0;
    const plaintext = data[0..plaintext_len];

    switch (version) {
        .tls_1_3 => {
            var inner_buf: [max_plaintext_len + 1]u8 = undefined;
            @memcpy(inner_buf[0..plaintext.len], plaintext);
            inner_buf[plaintext.len] = @intFromEnum(content_type);
            const inner = inner_buf[0 .. plaintext.len + 1];

            var hdr: [record_header_len]u8 = undefined;
            const hdr_val = RecordHeader{
                .content_type = .application_data,
                .version = .tls_1_2,
                .length = @intCast(inner.len + 16),
            };
            hdr_val.format(&hdr);
            const nonce_val = nonceTLS13(&iv, seq.*);

            var out_buf: [max_record_len]u8 = undefined;
            @memcpy(out_buf[0..record_header_len], &hdr);
            const enc_len = switch (cipher_suite) {
                .AES_128_GCM_SHA256 => blk: {
                    var k: [16]u8 = undefined;
                    @memcpy(&k, key[0..16]);
                    const enc = try encryptTLS13(crypto.aead.aes_gcm.Aes128Gcm, out_buf[record_header_len..], inner, &hdr, &nonce_val, &k);
                    break :blk enc.len;
                },
                .AES_256_GCM_SHA384 => blk: {
                    var k: [32]u8 = undefined;
                    @memcpy(&k, key[0..32]);
                    const enc = try encryptTLS13(crypto.aead.aes_gcm.Aes256Gcm, out_buf[record_header_len..], inner, &hdr, &nonce_val, &k);
                    break :blk enc.len;
                },
                .CHACHA20_POLY1305_SHA256 => blk: {
                    var k: [32]u8 = undefined;
                    @memcpy(&k, key[0..32]);
                    const enc = try encryptTLS13(crypto.aead.chacha_poly.ChaCha20Poly1305, out_buf[record_header_len..], inner, &hdr, &nonce_val, &k);
                    break :blk enc.len;
                },
                else => return error.TlsUnsupportedCipherSuite,
            };
            sender.sendAll(out_buf[0 .. record_header_len + enc_len]) catch return error.WriteFailed;
        },
        .tls_1_2 => {
            const ciphertext_len = try tls12CiphertextLen(cipher_suite, plaintext.len);
            var hdr: [record_header_len]u8 = undefined;
            const hdr_val = RecordHeader{
                .content_type = content_type,
                .version = .tls_1_2,
                .length = @intCast(ciphertext_len),
            };
            hdr_val.format(&hdr);

            var out_buf: [max_record_len]u8 = undefined;
            @memcpy(out_buf[0..record_header_len], &hdr);
            const encrypted = try encryptTLS12ForSuite(
                out_buf[record_header_len..],
                plaintext,
                &hdr,
                seq.*,
                &iv,
                &key,
                cipher_suite,
            );
            const enc_len = encrypted.len;
            std.debug.assert(enc_len == ciphertext_len);
            sender.sendAll(out_buf[0 .. record_header_len + enc_len]) catch return error.WriteFailed;
        },
        else => return error.TlsUnsupportedCipherSuite,
    }

    seq.* += 1;
    return plaintext.len;
}

fn writeAllBoundedRecords(writer: anytype, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const n = try writer.write(data[written..]);
        if (n == 0 or n > data.len - written) return error.WriteFailed;
        written += n;
    }
}

fn returnApplicationPlaintext(
    read_buf: *[max_record_len]u8,
    read_buf_len: *usize,
    read_buf_pos: *usize,
    output: []u8,
    plaintext: []const u8,
) usize {
    const to_copy = @min(plaintext.len, output.len);
    @memmove(output[0..to_copy], plaintext[0..to_copy]);

    const remaining = plaintext.len - to_copy;
    if (remaining > 0) {
        @memmove(read_buf[0..remaining], plaintext[to_copy..]);
        read_buf_len.* = remaining;
        read_buf_pos.* = 0;
    } else {
        read_buf_len.* = 0;
        read_buf_pos.* = 0;
    }
    return to_copy;
}

const ApplicationRecord = struct {
    content_type: u8,
    content: []u8,
};

const ApplicationReadState = struct {
    socket: *Socket,
    context: ?*const IoContext = null,
    version: tls.ProtocolVersion,
    is_server: bool,
    cipher_suite: tls.CipherSuite,
    app_write_key: *?[32]u8,
    app_write_iv: *?[12]u8,
    app_write_secret: *?[48]u8,
    app_read_key: *?[32]u8,
    app_read_iv: *?[12]u8,
    app_read_secret: *?[48]u8,
    write_seq: *u64,
    read_seq: *u64,
    read_buf: *[max_record_len]u8,
    read_buf_len: *usize,
    read_buf_pos: *usize,
    encrypted_buf: *[max_record_len]u8,
    encrypted_buf_len: *usize,
    encrypted_buf_pos: *usize,
    post_handshake_buf: *[max_post_handshake_buffer_len]u8,
    post_handshake_len: *usize,
};

fn parseTLS13InnerPlaintext(plaintext: []u8) !ApplicationRecord {
    var content_type_pos = plaintext.len;
    while (content_type_pos > 0) {
        content_type_pos -= 1;
        if (plaintext[content_type_pos] != 0) {
            return .{
                .content_type = plaintext[content_type_pos],
                .content = plaintext[0..content_type_pos],
            };
        }
    }
    return error.TlsUnexpectedMessage;
}

fn updateTLS13TrafficKeys(
    cipher_suite: tls.CipherSuite,
    secret: *[48]u8,
    key: *[32]u8,
    iv: *[12]u8,
) !void {
    switch (cipher_suite) {
        .AES_128_GCM_SHA256, .CHACHA20_POLY1305_SHA256 => {
            const updated_secret = hkdfExpandLabel(secret[0..32], "traffic upd", "", 32);
            @memset(secret, 0);
            @memcpy(secret[0..updated_secret.len], &updated_secret);
            const keys = deriveTrafficKeys13(&updated_secret);
            @memset(key, 0);
            if (cipher_suite == .AES_128_GCM_SHA256) {
                @memcpy(key[0..keys.key16.len], &keys.key16);
            } else {
                key.* = keys.key32;
            }
            iv.* = keys.iv;
        },
        .AES_256_GCM_SHA384 => {
            const updated_secret = hkdfExpandLabel(secret, "traffic upd", "", 48);
            secret.* = updated_secret;
            const keys = deriveTrafficKeys13(&updated_secret);
            key.* = keys.key32;
            iv.* = keys.iv;
        },
        else => return error.TlsUnsupportedCipherSuite,
    }
}

fn validateNewSessionTicket(body: []const u8) !void {
    if (body.len < 13) return error.TlsDecodeError;

    var offset: usize = 8;
    const nonce_len = body[offset];
    offset += 1;
    if (offset + nonce_len > body.len) return error.TlsDecodeError;
    offset += nonce_len;

    if (offset + 2 > body.len) return error.TlsDecodeError;
    const ticket_len = mem.readInt(u16, body[offset..][0..2], .big);
    offset += 2;
    if (ticket_len == 0 or offset + ticket_len > body.len) return error.TlsDecodeError;
    offset += ticket_len;

    if (offset + 2 > body.len) return error.TlsDecodeError;
    const extensions_len = mem.readInt(u16, body[offset..][0..2], .big);
    offset += 2;
    if (offset + extensions_len != body.len) return error.TlsDecodeError;

    const extensions_end = offset + extensions_len;
    while (offset < extensions_end) {
        if (extensions_end - offset < 4) return error.TlsDecodeError;
        const extension_len = mem.readInt(u16, body[offset + 2 ..][0..2], .big);
        offset += 4;
        if (extension_len > extensions_end - offset) return error.TlsDecodeError;
        offset += extension_len;
    }
}

fn handleKeyUpdate(state: *ApplicationReadState, body: []const u8) !void {
    if (body.len != 1) return error.TlsDecodeError;
    const request: tls.KeyUpdateRequest = @enumFromInt(body[0]);
    switch (request) {
        .update_not_requested, .update_requested => {},
        _ => return error.TlsIllegalParameter,
    }

    const read_secret = if (state.app_read_secret.*) |*secret|
        secret
    else
        return error.TlsHandshakeNotComplete;
    const read_key = if (state.app_read_key.*) |*key|
        key
    else
        return error.TlsHandshakeNotComplete;
    const read_iv = if (state.app_read_iv.*) |*iv|
        iv
    else
        return error.TlsHandshakeNotComplete;

    var write_secret: ?*[48]u8 = null;
    var write_key: ?*[32]u8 = null;
    var write_iv: ?*[12]u8 = null;
    if (request == .update_requested) {
        write_secret = if (state.app_write_secret.*) |*secret|
            secret
        else
            return error.TlsHandshakeNotComplete;
        write_key = if (state.app_write_key.*) |*key|
            key
        else
            return error.TlsHandshakeNotComplete;
        write_iv = if (state.app_write_iv.*) |*iv|
            iv
        else
            return error.TlsHandshakeNotComplete;
    }

    try updateTLS13TrafficKeys(state.cipher_suite, read_secret, read_key, read_iv);
    state.read_seq.* = 0;

    if (request == .update_requested) {
        const response = [_]u8{
            @intFromEnum(tls.HandshakeType.key_update),
            0,
            0,
            1,
            @intFromEnum(tls.KeyUpdateRequest.update_not_requested),
        };
        _ = try writeBoundedEncryptedRecord(
            state.socket,
            .tls_1_3,
            write_key.?.*,
            write_iv.?.*,
            state.cipher_suite,
            state.write_seq,
            &response,
            .handshake,
        );
        try updateTLS13TrafficKeys(state.cipher_suite, write_secret.?, write_key.?, write_iv.?);
        state.write_seq.* = 0;
    }
}

fn processPostHandshake(state: *ApplicationReadState, fragment: []const u8) !void {
    if (fragment.len > state.post_handshake_buf.len - state.post_handshake_len.*) {
        return error.TlsRecordOverflow;
    }
    @memcpy(
        state.post_handshake_buf[state.post_handshake_len.*..][0..fragment.len],
        fragment,
    );
    state.post_handshake_len.* += fragment.len;

    while (state.post_handshake_len.* >= 4) {
        const handshake_type = state.post_handshake_buf[0];
        const body_len: usize = mem.readInt(u24, state.post_handshake_buf[1..4], .big);

        switch (handshake_type) {
            @intFromEnum(tls.HandshakeType.new_session_ticket) => {
                if (state.is_server) return error.TlsUnexpectedMessage;
                if (body_len > max_new_session_ticket_body_len) return error.TlsRecordOverflow;
            },
            @intFromEnum(tls.HandshakeType.key_update) => {
                if (body_len != 1) return error.TlsDecodeError;
            },
            else => return error.TlsUnexpectedMessage,
        }

        const message_len = 4 + body_len;
        if (message_len > state.post_handshake_buf.len) return error.TlsRecordOverflow;
        if (state.post_handshake_len.* < message_len) return;

        const body = state.post_handshake_buf[4..message_len];
        switch (handshake_type) {
            @intFromEnum(tls.HandshakeType.new_session_ticket) => {
                try validateNewSessionTicket(body);
            },
            @intFromEnum(tls.HandshakeType.key_update) => {
                if (state.post_handshake_len.* != message_len) {
                    return error.TlsUnexpectedMessage;
                }
                try handleKeyUpdate(state, body);
                state.post_handshake_len.* = 0;
                return;
            },
            else => unreachable,
        }

        const remaining = state.post_handshake_len.* - message_len;
        if (remaining > 0) {
            @memmove(
                state.post_handshake_buf[0..remaining],
                state.post_handshake_buf[message_len..][0..remaining],
            );
        }
        state.post_handshake_len.* = remaining;
    }
}

fn dispatchApplicationRecord(
    state: *ApplicationReadState,
    record: ApplicationRecord,
) !?[]u8 {
    return switch (record.content_type) {
        @intFromEnum(ContentType.application_data) => {
            if (state.post_handshake_len.* != 0) return error.TlsUnexpectedMessage;
            return record.content;
        },
        @intFromEnum(ContentType.alert) => {
            if (record.content.len != 2) return error.TlsDecodeError;
            const description: tls.Alert.Description = @enumFromInt(record.content[1]);
            return errors.fromAlert(description);
        },
        @intFromEnum(ContentType.handshake) => {
            if (state.version != .tls_1_3) return error.TlsUnexpectedMessage;
            try processPostHandshake(state, record.content);
            return null;
        },
        else => error.TlsUnexpectedMessage,
    };
}

fn readEncryptedBytes(state: *ApplicationReadState, output: []u8) !usize {
    if (state.encrypted_buf_pos.* < state.encrypted_buf_len.*) {
        const available = state.encrypted_buf_len.* - state.encrypted_buf_pos.*;
        const to_copy = @min(available, output.len);
        @memcpy(
            output[0..to_copy],
            state.encrypted_buf[state.encrypted_buf_pos.*..][0..to_copy],
        );
        state.encrypted_buf_pos.* += to_copy;
        if (state.encrypted_buf_pos.* == state.encrypted_buf_len.*) {
            state.encrypted_buf_pos.* = 0;
            state.encrypted_buf_len.* = 0;
        }
        return to_copy;
    }

    return (if (state.context) |context|
        state.socket.recvWithContext(output, context)
    else
        state.socket.recv(output)) catch |err| switch (err) {
        error.ConnectionResetByPeer => error.TlsConnectionTruncated,
        error.Cancelled, error.Timeout => |context_err| context_err,
        else => error.ReadFailed,
    };
}

fn readApplicationData(state: *ApplicationReadState, output: []u8) !usize {
    if (state.app_read_key.* == null or state.app_read_iv.* == null) {
        return error.TlsHandshakeNotComplete;
    }
    if (output.len == 0) return 0;

    if (state.read_buf_pos.* < state.read_buf_len.*) {
        const available = state.read_buf_len.* - state.read_buf_pos.*;
        const to_copy = @min(available, output.len);
        @memcpy(output[0..to_copy], state.read_buf[state.read_buf_pos.*..][0..to_copy]);
        state.read_buf_pos.* += to_copy;
        return to_copy;
    }

    var skipped_records: usize = 0;
    while (true) {
        var total: usize = 0;
        while (total < record_header_len) {
            const n = try readEncryptedBytes(state, state.read_buf[total..record_header_len]);
            if (n == 0) return error.TlsConnectionTruncated;
            total += n;
        }

        const length = mem.readInt(u16, state.read_buf[3..5], .big);
        if (length > max_ciphertext_len) return error.TlsRecordOverflow;
        while (total < record_header_len + length) {
            const n = try readEncryptedBytes(
                state,
                state.read_buf[total..][0 .. record_header_len + length - total],
            );
            if (n == 0) return error.TlsConnectionTruncated;
            total += n;
        }

        const header = state.read_buf[0..record_header_len];
        const record_body = state.read_buf[record_header_len..][0..length];
        const read_key = state.app_read_key.* orelse return error.TlsHandshakeNotComplete;
        const read_iv = state.app_read_iv.* orelse return error.TlsHandshakeNotComplete;
        const record = switch (state.version) {
            .tls_1_3 => blk: {
                if (header[0] != @intFromEnum(ContentType.application_data)) {
                    return error.TlsUnexpectedMessage;
                }
                const plaintext = try decryptTLS13ForSuite(
                    record_body,
                    header,
                    state.read_seq.*,
                    &read_iv,
                    &read_key,
                    state.cipher_suite,
                );
                state.read_seq.* += 1;
                break :blk try parseTLS13InnerPlaintext(plaintext);
            },
            .tls_1_2 => blk: {
                const plaintext = try decryptTLS12ForSuite(
                    record_body,
                    header,
                    state.read_seq.*,
                    &read_iv,
                    &read_key,
                    state.cipher_suite,
                );
                state.read_seq.* += 1;
                break :blk ApplicationRecord{
                    .content_type = header[0],
                    .content = plaintext,
                };
            },
            else => return error.TlsUnsupportedCipherSuite,
        };

        const application_data = try dispatchApplicationRecord(state, record);
        if (application_data) |data| {
            if (data.len > 0) {
                return returnApplicationPlaintext(
                    state.read_buf,
                    state.read_buf_len,
                    state.read_buf_pos,
                    output,
                    data,
                );
            }
        }

        skipped_records += 1;
        if (skipped_records > max_skipped_records_per_read) {
            return error.TlsUnexpectedMessage;
        }
    }
}

pub fn hmacSha256Expand(secret: []const u8, label: []const u8, seed: []const u8, out: []u8) void {
    const Hmac = crypto.auth.hmac.sha2.HmacSha256;
    const ls_len = label.len + seed.len;
    var ls: [128]u8 = undefined;
    @memcpy(ls[0..label.len], label);
    @memcpy(ls[label.len..][0..seed.len], seed);
    // RFC 5246 §5:
    //   A(0) = label || seed
    //   A(i) = HMAC(secret, A(i-1))        <- NO seed in the A-chain
    //   output = HMAC(secret, A(1)||label||seed) || HMAC(secret, A(2)||label||seed) || ...
    var a: [32]u8 = undefined;
    var result: [32]u8 = undefined;
    Hmac.create(&a, ls[0..ls_len], secret); // A(1)
    var offset: usize = 0;
    while (offset + 32 <= out.len) : (offset += 32) {
        var a_ls: [32 + 128]u8 = undefined;
        @memcpy(a_ls[0..32], &a);
        @memcpy(a_ls[32..][0..ls_len], ls[0..ls_len]);
        Hmac.create(&result, a_ls[0 .. 32 + ls_len], secret);
        @memcpy(out[offset..][0..32], &result);
        Hmac.create(&a, &a, secret); // A(i+1) = HMAC(A(i))
    }
    if (offset < out.len) {
        var a_ls: [32 + 128]u8 = undefined;
        @memcpy(a_ls[0..32], &a);
        @memcpy(a_ls[32..][0..ls_len], ls[0..ls_len]);
        Hmac.create(&result, a_ls[0 .. 32 + ls_len], secret);
        @memcpy(out[offset..], result[0 .. out.len - offset]);
    }
}

pub fn hmacSha384Expand(secret: []const u8, label: []const u8, seed: []const u8, out: []u8) void {
    const Hmac = crypto.auth.hmac.sha2.HmacSha384;
    const ls_len = label.len + seed.len;
    var ls: [128]u8 = undefined;
    @memcpy(ls[0..label.len], label);
    @memcpy(ls[label.len..][0..seed.len], seed);
    var a: [48]u8 = undefined;
    var result: [48]u8 = undefined;
    Hmac.create(&a, ls[0..ls_len], secret); // A(1)
    var offset: usize = 0;
    while (offset + 48 <= out.len) : (offset += 48) {
        var a_ls: [48 + 128]u8 = undefined;
        @memcpy(a_ls[0..48], &a);
        @memcpy(a_ls[48..][0..ls_len], ls[0..ls_len]);
        Hmac.create(&result, a_ls[0 .. 48 + ls_len], secret);
        @memcpy(out[offset..][0..48], &result);
        Hmac.create(&a, &a, secret); // A(i+1) = HMAC(A(i))
    }
    if (offset < out.len) {
        var a_ls: [48 + 128]u8 = undefined;
        @memcpy(a_ls[0..48], &a);
        @memcpy(a_ls[48..][0..ls_len], ls[0..ls_len]);
        Hmac.create(&result, a_ls[0 .. 48 + ls_len], secret);
        @memcpy(out[offset..], result[0 .. out.len - offset]);
    }
}

/// TLS 1.2 master secret is ALWAYS 48 bytes regardless of cipher hash
/// (RFC 5246 §6.1): P_hash with the suite's hash, here SHA-256.
pub fn deriveMasterSecret256(
    pre_master_secret: *const [32]u8,
    client_random: *const [32]u8,
    server_random: *const [32]u8,
) [48]u8 {
    const seed = client_random.* ++ server_random.*;
    var master_secret: [48]u8 = undefined;
    hmacSha256Expand(pre_master_secret, "master secret", &seed, &master_secret);
    return master_secret;
}

pub fn deriveMasterSecret384(
    pre_master_secret: *const [32]u8,
    client_random: *const [32]u8,
    server_random: *const [32]u8,
) [48]u8 {
    const seed = client_random.* ++ server_random.*;
    var master_secret: [48]u8 = undefined;
    hmacSha384Expand(pre_master_secret, "master secret", &seed, &master_secret);
    return master_secret;
}

pub fn deriveKeyBlock256(
    master_secret: *const [48]u8,
    server_random: *const [32]u8,
    client_random: *const [32]u8,
    comptime length: usize,
) [length]u8 {
    const seed = server_random.* ++ client_random.*;
    var key_block: [length]u8 = undefined;
    hmacSha256Expand(master_secret, "key expansion", &seed, &key_block);
    return key_block;
}

pub fn deriveKeyBlock384(
    master_secret: *const [48]u8,
    server_random: *const [32]u8,
    client_random: *const [32]u8,
    comptime length: usize,
) [length]u8 {
    const seed = server_random.* ++ client_random.*;
    var key_block: [length]u8 = undefined;
    hmacSha384Expand(master_secret, "key expansion", &seed, &key_block);
    return key_block;
}

pub fn hkdfExtract(ikm: []const u8, salt: []const u8, comptime hash_len: usize) [hash_len]u8 {
    if (hash_len == 32) {
        const Hmac = crypto.auth.hmac.sha2.HmacSha256;
        var prk: [hash_len]u8 = undefined;
        Hmac.create(&prk, ikm, salt);
        return prk;
    } else {
        const Hmac = crypto.auth.hmac.sha2.HmacSha384;
        var prk: [hash_len]u8 = undefined;
        Hmac.create(&prk, ikm, salt);
        return prk;
    }
}

pub fn hkdfExpandLabel(
    prk: []const u8,
    comptime label: []const u8,
    context: []const u8,
    comptime out_len: usize,
) [out_len]u8 {
    const max_label_len = 255;
    const max_context_len = 255;
    const tls13 = "tls13 ";
    var buf: [2 + 1 + tls13.len + max_label_len + 1 + max_context_len]u8 = undefined;
    // RFC 8446 Section 7.1: HkdfLabel = uint16 length || opaque label<7..255-1> || opaque context<0..255-1>
    // The u16 length field is the desired OUTPUT length, NOT the size of the info buffer.
    mem.writeInt(u16, buf[0..2], out_len, .big);
    buf[2] = @as(u8, @intCast(tls13.len + label.len));
    buf[3..][0..tls13.len].* = tls13.*;
    var i: usize = 3 + tls13.len;
    @memcpy(buf[i..][0..label.len], label);
    i += label.len;
    buf[i] = @as(u8, @intCast(context.len));
    i += 1;
    @memcpy(buf[i..][0..context.len], context);
    i += context.len;
    const info = buf[0..i];

    // HKDF-Expand with the hash matching the PRK length (RFC 8446 §7.1:
    // secrets are 32 bytes for SHA-256 suites, 48 for SHA-384 suites).
    if (prk.len == 32) {
        return hkdfExpandT(crypto.auth.hmac.sha2.HmacSha256, prk, info, out_len);
    } else {
        return hkdfExpandT(crypto.auth.hmac.sha2.HmacSha384, prk, info, out_len);
    }
}

fn hkdfExpandT(comptime Hmac: type, prk: []const u8, info: []const u8, comptime out_len: usize) [out_len]u8 {
    const mac_len = Hmac.mac_length;
    var result: [out_len]u8 = undefined;
    // T(1) = HMAC(PRK, info || 0x01)
    var a: [mac_len]u8 = undefined;
    var st = Hmac.init(prk);
    st.update(info);
    st.update(&[_]u8{0x01});
    st.final(&a);
    var offset: usize = @min(out_len, mac_len);
    @memcpy(result[0..offset], a[0..offset]);
    // T(i) = HMAC(PRK, T(i-1) || info || i)
    var counter: u8 = 2;
    while (offset < out_len) : (counter += 1) {
        st = Hmac.init(prk);
        st.update(&a);
        st.update(info);
        st.update(&[_]u8{counter});
        st.final(&a);
        const take = @min(mac_len, out_len - offset);
        @memcpy(result[offset..][0..take], a[0..take]);
        offset += take;
    }
    return result;
}

pub fn deriveHandshakeSecret13(
    shared_secret: []const u8,
    comptime hash_len: usize,
) [hash_len]u8 {
    // TLS 1.3 key derivation (RFC 8446 Section 7.1):
    // 1. early_secret = HKDF-Extract(zero PSK, zero salt) — both are hash_len zeros
    // 2. derived_secret = HKDF-Expand-Label(early_secret, "derived", Hash(""), hash_len)
    //    Hash("") = empty hash digest (32 bytes of SHA-256 or 48 bytes of SHA-384)
    // 3. handshake_secret = HKDF-Extract(handshake_derived_secret, shared_secret)
    //
    // Note: hkdfExtract(ikm, salt) = HKDF-Extract(salt, ikm)
    const zero_psk: [hash_len]u8 = .{0} ** hash_len;
    const zero_salt: [hash_len]u8 = .{0} ** hash_len;
    const early_secret = hkdfExtract(&zero_psk, &zero_salt, hash_len);

    // Compute Hash("") — the hash of an empty string, used as context for "derived"
    const empty_hash: [hash_len]u8 = blk: {
        if (hash_len == 32) {
            var h = crypto.hash.sha2.Sha256.init(.{});
            var result: [32]u8 = undefined;
            h.final(&result);
            break :blk result;
        } else {
            var h = crypto.hash.sha2.Sha384.init(.{});
            var result: [48]u8 = undefined;
            h.final(&result);
            break :blk result;
        }
    };

    const handshake_derived_secret = hkdfExpandLabel(&early_secret, "derived", &empty_hash, hash_len);
    // HKDF-Extract(handshake_derived_secret, shared_secret)
    // = hkdfExtract(ikm=shared_secret, salt=handshake_derived_secret)
    return hkdfExtract(shared_secret, &handshake_derived_secret, hash_len);
}

/// Derives record protection keys and IVs from a traffic secret.
/// The requested length feeds the HKDF label info, so key16 is NOT a prefix
/// of key32. Callers pick per cipher: 16 for AES-128-GCM, 32 for AES-256-
/// GCM and ChaCha20-Poly1305. IV is always 12 bytes.
pub fn deriveTrafficKeys13(
    secret: []const u8,
) struct { key16: [16]u8, key32: [32]u8, iv: [12]u8 } {
    return .{
        .key16 = hkdfExpandLabel(secret, "key", "", 16),
        .key32 = hkdfExpandLabel(secret, "key", "", 32),
        .iv = hkdfExpandLabel(secret, "iv", "", 12),
    };
}

/// Selects the record-protection key bytes for `cs` from a deriveTrafficKeys13
/// result. `keys` must be passed by pointer so the returned slice stays valid.
pub fn trafficKeyFor(cs: tls.CipherSuite, keys: anytype) []const u8 {
    return switch (cs) {
        .AES_128_GCM_SHA256 => &keys.*.key16,
        else => &keys.*.key32,
    };
}

pub fn readTLSRecord(socket: *Socket, buf: *[4096]u8) ![]const u8 {
    var total: usize = 0;
    while (total < 5) {
        const n = socket.recv(buf[total..5]) catch |err| switch (err) {
            error.ConnectionResetByPeer => return error.TlsConnectionTruncated,
            else => return error.ReadFailed,
        };
        if (n == 0) return error.TlsConnectionTruncated;
        total += n;
    }
    const length = mem.readInt(u16, buf[3..5], .big);
    if (length > max_ciphertext_len) return error.TlsRecordOverflow;
    while (total < 5 + length) {
        const n = socket.recv(buf[total..][0 .. 5 + length - total]) catch |err| switch (err) {
            error.ConnectionResetByPeer => return error.TlsConnectionTruncated,
            else => return error.ReadFailed,
        };
        if (n == 0) return error.TlsConnectionTruncated;
        total += n;
    }
    return buf[5..][0..length];
}

fn readHandshakeRecord(socket: *Socket, buf: *[4096]u8) ![]const u8 {
    const data = try readTLSRecord(socket, buf);
    switch (buf[0]) {
        @intFromEnum(ContentType.handshake) => return data,
        @intFromEnum(ContentType.alert) => {
            if (data.len >= 2) {
                const alert_desc: tls.Alert.Description = @enumFromInt(data[1]);
                return errors.fromAlert(alert_desc);
            }
            return error.TlsHandshakeFailure;
        },
        @intFromEnum(ContentType.change_cipher_spec) => return data,
        else => return error.TlsUnexpectedMessage,
    }
}

pub fn sendTLSHandshakeRecord(socket: *Socket, msg: []const u8) !void {
    var buf: [5 + max_plaintext_len]u8 = undefined;
    buf[0] = @intFromEnum(ContentType.handshake);
    buf[1] = 0x03;
    buf[2] = 0x03;
    mem.writeInt(u16, buf[3..5], @intCast(msg.len), .big);
    @memcpy(buf[5..][0..msg.len], msg);
    socket.sendAll(buf[0 .. 5 + msg.len]) catch return error.WriteFailed;
}

pub fn sendTLSChangeCipherSpec(socket: *Socket) !void {
    // RFC 5246 §6.2.1: every TLS 1.2 record — including CCS — carries
    // legacy_version 0x0303.
    const ccs = [_]u8{
        @intFromEnum(ContentType.change_cipher_spec),
        0x03,
        0x03,
        0x00,
        0x01,
        0x01,
    };
    socket.sendAll(&ccs) catch return error.WriteFailed;
}

/// Send a TLS 1.2 handshake message protected with the negotiated AEAD
/// (RFC 5246): outer record keeps content_type=handshake and version 0x0303.
pub fn sendTLS12EncryptedHandshake(
    socket: *Socket,
    msg: []const u8,
    key: []const u8,
    iv: *const [12]u8,
    seq: *u64,
    cs: tls.CipherSuite,
) !void {
    const ciphertext_len = try tls12CiphertextLen(cs, msg.len);
    var hdr_buf: [record_header_len]u8 = undefined;
    const hdr_val = RecordHeader{
        .content_type = .handshake,
        .version = .tls_1_2,
        .length = @intCast(ciphertext_len),
    };
    hdr_val.format(&hdr_buf);

    var out_buf: [record_header_len + max_plaintext_len + 256]u8 = undefined;
    @memcpy(out_buf[0..record_header_len], &hdr_buf);

    var key_buf: [32]u8 = .{0} ** 32;
    if (key.len > key_buf.len) return error.TlsUnsupportedCipherSuite;
    @memcpy(key_buf[0..key.len], key);
    const encrypted = try encryptTLS12ForSuite(
        out_buf[record_header_len..],
        msg,
        &hdr_buf,
        seq.*,
        iv,
        &key_buf,
        cs,
    );
    const enc_len = encrypted.len;
    std.debug.assert(enc_len == ciphertext_len);

    socket.sendAll(out_buf[0 .. record_header_len + enc_len]) catch return error.WriteFailed;
    seq.* += 1;
}

/// Read one AEAD-protected TLS 1.2 record (handshake or application_data)
/// and return the decrypted plaintext.
pub fn readTLS12EncryptedRecord(
    socket: *Socket,
    buf: *[4096]u8,
    key: []const u8,
    iv: *const [12]u8,
    seq: *u64,
    cs: tls.CipherSuite,
) ![]const u8 {
    var total: usize = 0;
    while (total < 5) {
        const n = socket.recv(buf[total..5]) catch |err| switch (err) {
            error.ConnectionResetByPeer => return error.TlsConnectionTruncated,
            else => return error.ReadFailed,
        };
        if (n == 0) return error.TlsConnectionTruncated;
        total += n;
    }
    switch (buf[0]) {
        @intFromEnum(ContentType.alert) => {
            if (buf[5] == 2) { // fatal
                return errors.fromAlert(@enumFromInt(buf[6]));
            }
            return error.TlsHandshakeFailure;
        },
        @intFromEnum(ContentType.handshake), @intFromEnum(ContentType.application_data) => {},
        else => return error.TlsUnexpectedMessage,
    }
    const length = mem.readInt(u16, buf[3..5], .big);
    if (length > max_ciphertext_len) return error.TlsRecordOverflow;
    while (total < 5 + length) {
        const n = socket.recv(buf[total..][0 .. 5 + length - total]) catch |err| switch (err) {
            error.ConnectionResetByPeer => return error.TlsConnectionTruncated,
            else => return error.ReadFailed,
        };
        if (n == 0) return error.TlsConnectionTruncated;
        total += n;
    }

    const hdr: *const [record_header_len]u8 = buf[0..5];
    const ct = buf[5..][0..length];
    var key_buf: [32]u8 = .{0} ** 32;
    if (key.len > key_buf.len) return error.TlsUnsupportedCipherSuite;
    @memcpy(key_buf[0..key.len], key);
    const plain = try decryptTLS12ForSuite(ct, hdr, seq.*, iv, &key_buf, cs);
    seq.* += 1;
    return plain;
}

pub fn sendTLS13EncryptedHandshake(
    socket: *Socket,
    msg: []const u8,
    key: []const u8,
    iv: []const u8,
    seq: *u64,
    cs: tls.CipherSuite,
) !void {
    var inner_buf: [max_plaintext_len + 1]u8 = undefined;
    @memcpy(inner_buf[0..msg.len], msg);
    inner_buf[msg.len] = @intFromEnum(ContentType.handshake);
    const inner_len = msg.len + 1;

    var hdr_buf: [record_header_len]u8 = undefined;
    const hdr_val = RecordHeader{
        .content_type = .application_data,
        .version = .tls_1_2,
        .length = @intCast(inner_len + 16),
    };
    hdr_val.format(&hdr_buf);

    var nonce_storage = nonceTLS13(iv[0..12], seq.*);
    const nonce = &nonce_storage;
    var out_buf: [record_header_len + max_plaintext_len + 256]u8 = undefined;
    @memcpy(out_buf[0..record_header_len], &hdr_buf);

    const enc_len = switch (cs) {
        .AES_128_GCM_SHA256 => blk: {
            var k: [16]u8 = undefined;
            @memcpy(&k, key[0..16]);
            const enc = try encryptTLS13(crypto.aead.aes_gcm.Aes128Gcm, out_buf[record_header_len..], inner_buf[0..inner_len], &hdr_buf, nonce, &k);
            break :blk enc.len;
        },
        .AES_256_GCM_SHA384 => blk: {
            var k: [32]u8 = undefined;
            @memcpy(&k, key[0..32]);
            const enc = try encryptTLS13(crypto.aead.aes_gcm.Aes256Gcm, out_buf[record_header_len..], inner_buf[0..inner_len], &hdr_buf, nonce, &k);
            break :blk enc.len;
        },
        .CHACHA20_POLY1305_SHA256 => blk: {
            var k: [32]u8 = undefined;
            @memcpy(&k, key[0..32]);
            const enc = try encryptTLS13(crypto.aead.chacha_poly.ChaCha20Poly1305, out_buf[record_header_len..], inner_buf[0..inner_len], &hdr_buf, nonce, &k);
            break :blk enc.len;
        },
        else => return error.TlsUnsupportedCipherSuite,
    };

    const total = record_header_len + enc_len;
    socket.sendAll(out_buf[0..total]) catch return error.WriteFailed;
    seq.* += 1;
}

pub fn readTLS13EncryptedHandshake(
    socket: *Socket,
    buf: *[4096]u8,
    key: []const u8,
    iv: []const u8,
    seq: *u64,
    cs: tls.CipherSuite,
) ![]const u8 {
    const record_data = try readTLSRecord(socket, buf);
    const hdr_ptr: *const [record_header_len]u8 = buf[0..record_header_len];
    var nonce_storage = nonceTLS13(iv[0..12], seq.*);
    const nonce = &nonce_storage;

    const decrypted = switch (cs) {
        .AES_128_GCM_SHA256 => blk: {
            var k: [16]u8 = undefined;
            @memcpy(&k, key[0..16]);
            break :blk try decryptTLS13(crypto.aead.aes_gcm.Aes128Gcm, @constCast(record_data), hdr_ptr, nonce, &k);
        },
        .AES_256_GCM_SHA384 => blk: {
            var k: [32]u8 = undefined;
            @memcpy(&k, key[0..32]);
            break :blk try decryptTLS13(crypto.aead.aes_gcm.Aes256Gcm, @constCast(record_data), hdr_ptr, nonce, &k);
        },
        .CHACHA20_POLY1305_SHA256 => blk: {
            var k: [32]u8 = undefined;
            @memcpy(&k, key[0..32]);
            break :blk try decryptTLS13(crypto.aead.chacha_poly.ChaCha20Poly1305, @constCast(record_data), hdr_ptr, nonce, &k);
        },
        else => return error.TlsUnsupportedCipherSuite,
    };

    seq.* += 1;
    if (decrypted.len == 0) return error.TlsDecryptError;
    return decrypted[0 .. decrypted.len - 1];
}

const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = crypto.auth.hmac.sha2.HmacSha384;

fn pemDecode(allocator: Allocator, pem: []const u8) ![]const u8 {
    const begin_marker = "-----BEGIN ";
    var start: usize = 0;
    var found_start = false;
    var i: usize = 0;
    while (i < pem.len) : (i += 1) {
        if (pem[i] == '-' and i + begin_marker.len <= pem.len) {
            if (mem.startsWith(u8, pem[i..], begin_marker)) {
                while (i < pem.len and pem[i] != '\n') : (i += 1) {}
                i += 1;
                start = i;
                found_start = true;
                break;
            }
        }
    }
    if (!found_start) return error.TlsInvalidPem;
    var end: usize = pem.len;
    i = start;
    while (i < pem.len) : (i += 1) {
        if (pem[i] == '-' and i + 5 <= pem.len) {
            if (mem.startsWith(u8, pem[i..], "-----END ")) {
                end = i;
                break;
            }
        }
    }
    var b64_len: usize = 0;
    for (pem[start..end]) |c| {
        if (c != '\n' and c != '\r' and c != ' ' and c != '\t') b64_len += 1;
    }
    var b64_buf = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64_buf);
    var pos: usize = 0;
    for (pem[start..end]) |c| {
        if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
            b64_buf[pos] = c;
            pos += 1;
        }
    }
    const Decoder = std.base64.standard.Decoder;
    const decoded_len = Decoder.calcSizeForSlice(b64_buf[0..b64_len]) catch return error.TlsInvalidPem;
    const decoded = try allocator.alloc(u8, decoded_len);
    Decoder.decode(decoded, b64_buf[0..b64_len]) catch {
        allocator.free(decoded);
        return error.TlsInvalidPem;
    };
    return decoded;
}

pub fn loadCertChain(allocator: Allocator, path: []const u8) ![]const []const u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    const dir = std.Io.Dir.cwd();
    const pem = try dir.readFileAlloc(io, path, allocator, .unlimited);
    defer allocator.free(pem);
    var count: usize = 0;
    var search_pos: usize = 0;
    while (search_pos < pem.len) {
        if (mem.indexOf(u8, pem[search_pos..], "-----BEGIN CERTIFICATE-----")) |_| {
            count += 1;
            if (mem.indexOf(u8, pem[search_pos..], "-----END CERTIFICATE-----")) |end_pos| {
                search_pos += end_pos + 25;
            } else break;
        } else break;
    }
    if (count == 0) return error.TlsNoCertificates;
    var certs = try allocator.alloc([]const u8, count);
    var cert_idx: usize = 0;
    search_pos = 0;
    while (cert_idx < count) {
        const begin_pos = mem.indexOf(u8, pem[search_pos..], "-----BEGIN CERTIFICATE-----") orelse break;
        const cert_start = search_pos + begin_pos;
        const end_pos = mem.indexOf(u8, pem[cert_start..], "-----END CERTIFICATE-----") orelse break;
        const cert_end = cert_start + end_pos + 25;
        certs[cert_idx] = try pemDecode(allocator, pem[cert_start..cert_end]);
        search_pos = cert_end;
        cert_idx += 1;
    }
    return certs;
}

pub fn loadPrivateKey(allocator: Allocator, path: []const u8) ![]const u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    const dir = std.Io.Dir.cwd();
    const pem = try dir.readFileAlloc(io, path, allocator, .unlimited);
    defer allocator.free(pem);
    const rsa_begin = "-----BEGIN RSA PRIVATE KEY-----";
    const pkcs8_begin = "-----BEGIN PRIVATE KEY-----";
    const ec_begin = "-----BEGIN EC PRIVATE KEY-----";
    const rsa_start = mem.indexOf(u8, pem, rsa_begin);
    const pkcs8_start = mem.indexOf(u8, pem, pkcs8_begin);
    const ec_start = mem.indexOf(u8, pem, ec_begin);
    const is_pkcs1 = rsa_start != null;
    const is_ec = ec_start != null and rsa_start == null;
    const final_start = if (rsa_start) |s| s else if (pkcs8_start) |s| s else ec_start orelse return error.TlsInvalidPrivateKey;
    const end_marker = if (is_pkcs1) "-----END RSA PRIVATE KEY-----" else if (is_ec) "-----END EC PRIVATE KEY-----" else "-----END PRIVATE KEY-----";
    const end_pos = mem.indexOf(u8, pem[final_start..], end_marker) orelse return error.TlsInvalidPrivateKey;
    const key_end = final_start + end_pos + end_marker.len;
    return pemDecode(allocator, pem[final_start..key_end]);
}

pub const ServerTLSConfig = struct {
    cert_chain_der: []const []const u8 = &.{},
    key_der: ?[]const u8 = null,
    allocator: ?Allocator = null,
    ecdsa_keypair: ?crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair = null,

    pub fn deinit(self: *ServerTLSConfig) void {
        if (self.allocator) |a| {
            for (self.cert_chain_der) |cert| a.free(cert);
            a.free(self.cert_chain_der);
            if (self.key_der) |k| a.free(k);
        }
    }
};

pub fn loadServerTLSConfig(allocator: Allocator, cert_path: []const u8, key_path: []const u8) !ServerTLSConfig {
    const cert_chain = try loadCertChain(allocator, cert_path);
    const key_der = try loadPrivateKey(allocator, key_path);
    var config = ServerTLSConfig{
        .cert_chain_der = cert_chain,
        .key_der = key_der,
        .allocator = allocator,
    };
    // Try to parse ECDSA P-256 private key from PKCS#8 DER
    if (config.key_der) |kd| {
        config.ecdsa_keypair = parseEcdsaP256KeyFromPkcs8(kd);
    }
    return config;
}

fn parseEcdsaP256KeyFromPkcs8(der: []const u8) ?crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair {
    // Supports both:
    // PKCS#8: SEQUENCE { INTEGER, SEQUENCE { OID, OID }, OCTET STRING { ECPrivateKey } }
    // SEC1:   SEQUENCE { INTEGER(1), OCTET STRING(32 bytes private key), [0] OID, [1] pub }
    // Strategy: recursively scan for OCTET STRING (tag 0x04) with exactly 32 bytes content.
    return scanDerForEcKey(der, 0, der.len);
}

fn scanDerForEcKey(der: []const u8, start: usize, end: usize) ?crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair {
    var i = start;
    while (i + 1 < end) {
        const tag = der[i];
        i += 1;
        if (i >= end) return null;
        var length: usize = 0;
        const len_byte = der[i];
        i += 1;
        if (len_byte < 0x80) {
            length = len_byte;
        } else if (len_byte == 0x81) {
            if (i >= end) return null;
            length = der[i];
            i += 1;
        } else if (len_byte == 0x82) {
            if (i + 1 >= end) return null;
            length = @as(usize, der[i]) << 8 | der[i + 1];
            i += 2;
        } else if (len_byte >= 0x83 and len_byte <= 0x86) {
            const len_len: usize = @intCast(len_byte & 0x0f);
            if (i + len_len > end) return null;
            length = 0;
            for (0..len_len) |j| {
                length = (length << 8) | der[i + j];
            }
            i += len_len;
        } else {
            i += length;
            continue;
        }
        if (i + length > end) return null;
        // OCTET STRING containing 32 bytes of EC private key
        if (tag == 0x04 and length == 32) {
            const raw_key: [32]u8 = der[i..][0..32].*;
            const sk = crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(raw_key) catch {
                i += length;
                continue;
            };
            return crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(sk) catch return null;
        }
        // If this is a constructed/SEQUENCE type (bit 5 set), descend into it
        if (tag & 0x20 != 0) {
            if (scanDerForEcKey(der, i, i + length)) |kp| return kp;
        }
        i += length;
    }
    return null;
}

pub const Connection = struct {
    allocator: Allocator,
    socket: *Socket,
    negotiated_alpn: alpn.NegotiatedAlpn = .{},
    tls_version: tls.ProtocolVersion = .tls_1_2,
    is_server: bool = false,
    connected: bool = false,
    app_write_key: ?[32]u8 = null,
    app_write_iv: ?[12]u8 = null,
    app_write_secret: ?[48]u8 = null,
    app_read_key: ?[32]u8 = null,
    app_read_iv: ?[12]u8 = null,
    app_read_secret: ?[48]u8 = null,
    write_seq: u64 = 0,
    read_seq: u64 = 0,
    hs_write_seq: u64 = 0,
    hs_read_seq: u64 = 0,
    cipher_suite: ?tls.CipherSuite = null,
    sni_hostname: ?[]const u8 = null,
    read_buf: [max_record_len]u8 = undefined,
    read_buf_len: usize = 0,
    read_buf_pos: usize = 0,
    encrypted_buf: [max_record_len]u8 = undefined,
    encrypted_buf_len: usize = 0,
    encrypted_buf_pos: usize = 0,
    post_handshake_buf: [max_post_handshake_buffer_len]u8 = undefined,
    post_handshake_len: usize = 0,

    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        return self.negotiated_alpn.get();
    }

    pub fn isHTTP2(self: *const Connection) bool {
        return self.negotiated_alpn.isHTTP2Result();
    }

    pub fn isHTTP3(self: *const Connection) bool {
        return self.negotiated_alpn.isHTTP3Result();
    }

    pub fn sniHostname(self: *const Connection) ?[]const u8 {
        return self.sni_hostname;
    }

    pub fn tlsVersion(self: *const Connection) tls.ProtocolVersion {
        return self.tls_version;
    }

    pub fn sendAlert(self: *Connection, level: tls.Alert.Level, desc: tls.Alert.Description) void {
        const payload = [_]u8{ @intFromEnum(level), @intFromEnum(desc) };
        // After the handshake completes, alerts MUST be encrypted under the
        // negotiated keys (RFC 5246 §7.2 / RFC 8446 §6).
        if (self.app_write_key != null and self.cipher_suite != null) {
            self.writeEncryptedRecord(&payload, .alert) catch {};
            return;
        }
        var buf: [7]u8 = undefined;
        buf[0] = @intFromEnum(ContentType.alert);
        buf[1] = 0x03;
        buf[2] = 0x03;
        buf[3] = 0;
        buf[4] = 2;
        buf[5] = payload[0];
        buf[6] = payload[1];
        _ = self.socket.send(buf[0..7]) catch {};
    }

    pub fn closeNotify(self: *Connection) void {
        self.sendAlert(.warning, .close_notify);
    }

    pub fn reader(self: *Connection) any_io.AnyReader {
        return .{
            .context = @ptrCast(self),
            .readFn = struct {
                fn read(ctx: *anyopaque, buffer: []u8) anyerror!usize {
                    const c: *Connection = @ptrCast(@alignCast(ctx));
                    return c.read(buffer);
                }
            }.read,
        };
    }

    pub fn writer(self: *Connection) any_io.AnyWriter {
        return .{
            .context = @ptrCast(self),
            .writeFn = struct {
                fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
                    const c: *Connection = @ptrCast(@alignCast(ctx));
                    return c.write(data);
                }
            }.write,
        };
    }

    /// Encrypts and sends one record of `ctype` under the negotiated keys.
    ///
    /// TLS 1.3: inner plaintext = msg || content_type (RFC 8446 §5.2),
    ///          outer record type is always application_data.
    /// TLS 1.2: outer record keeps the real content type (RFC 5246).
    pub fn writeEncryptedRecord(self: *Connection, data: []const u8, ctype: tls.ContentType) !void {
        if (data.len > max_plaintext_len) return error.TlsRecordOverflow;
        _ = try self.writeRecord(data, ctype);
    }

    fn writeRecord(self: *Connection, data: []const u8, ctype: tls.ContentType) !usize {
        const key = self.app_write_key orelse return error.TlsHandshakeNotComplete;
        const iv = self.app_write_iv orelse return error.TlsHandshakeNotComplete;
        const cs = self.cipher_suite orelse return error.TlsHandshakeNotComplete;
        return writeBoundedEncryptedRecord(self.socket, self.tls_version, key, iv, cs, &self.write_seq, data, ctype);
    }

    /// Sends at most one TLS application-data record.
    pub fn write(self: *Connection, data: []const u8) !usize {
        return self.writeRecord(data, .application_data);
    }

    pub fn writeWithContext(self: *Connection, data: []const u8, context: *const IoContext) !usize {
        const key = self.app_write_key orelse return error.TlsHandshakeNotComplete;
        const iv = self.app_write_iv orelse return error.TlsHandshakeNotComplete;
        const cs = self.cipher_suite orelse return error.TlsHandshakeNotComplete;
        var sender = ContextSocketSender{ .socket = self.socket, .context = context };
        return writeBoundedEncryptedRecord(&sender, self.tls_version, key, iv, cs, &self.write_seq, data, .application_data) catch |err| {
            try context.check();
            return err;
        };
    }

    /// Sends the complete application buffer as independently framed records.
    pub fn writeAll(self: *Connection, data: []const u8) !void {
        return writeAllBoundedRecords(self, data);
    }

    pub fn writeAllWithContext(self: *Connection, data: []const u8, context: *const IoContext) !void {
        var written: usize = 0;
        while (written < data.len) {
            const n = try self.writeWithContext(data[written..], context);
            if (n == 0 or n > data.len - written) return error.WriteFailed;
            written += n;
        }
    }

    pub fn flush(_: *Connection) !void {}

    pub fn read(self: *Connection, buf: []u8) !usize {
        return self.readInternal(buf, null);
    }

    pub fn readWithContext(self: *Connection, buf: []u8, context: *const IoContext) !usize {
        return self.readInternal(buf, context);
    }

    fn readInternal(self: *Connection, buf: []u8, context: ?*const IoContext) !usize {
        const cs = self.cipher_suite orelse return error.TlsHandshakeNotComplete;
        var state = ApplicationReadState{
            .socket = self.socket,
            .context = context,
            .version = self.tls_version,
            .is_server = self.is_server,
            .cipher_suite = cs,
            .app_write_key = &self.app_write_key,
            .app_write_iv = &self.app_write_iv,
            .app_write_secret = &self.app_write_secret,
            .app_read_key = &self.app_read_key,
            .app_read_iv = &self.app_read_iv,
            .app_read_secret = &self.app_read_secret,
            .write_seq = &self.write_seq,
            .read_seq = &self.read_seq,
            .read_buf = &self.read_buf,
            .read_buf_len = &self.read_buf_len,
            .read_buf_pos = &self.read_buf_pos,
            .encrypted_buf = &self.encrypted_buf,
            .encrypted_buf_len = &self.encrypted_buf_len,
            .encrypted_buf_pos = &self.encrypted_buf_pos,
            .post_handshake_buf = &self.post_handshake_buf,
            .post_handshake_len = &self.post_handshake_len,
        };
        return readApplicationData(&state, buf);
    }
};

const ContextSocketSender = struct {
    socket: *Socket,
    context: *const IoContext,

    fn sendAll(self: *@This(), data: []const u8) !void {
        return self.socket.sendAllWithContext(data, self.context);
    }
};

pub const TLSConfig = struct {
    allocator: Allocator,
    alpn_protocols: []const []const u8 = &.{"http/1.1"},
    verify_server: bool = true,
    ca_bundle_path: ?[]const u8 = null,

    pub fn init(allocator: Allocator) TLSConfig {
        return .{ .allocator = allocator };
    }

    pub fn insecure(allocator: Allocator) TLSConfig {
        return .{ .allocator = allocator, .verify_server = false };
    }

    pub fn withH2(allocator: Allocator) TLSConfig {
        return .{ .allocator = allocator, .alpn_protocols = &.{ "h2", "http/1.1" } };
    }

    pub fn insecureWithH2(allocator: Allocator) TLSConfig {
        return .{ .allocator = allocator, .alpn_protocols = &.{ "h2", "http/1.1" }, .verify_server = false };
    }

    pub fn withH3(allocator: Allocator) TLSConfig {
        return .{ .allocator = allocator, .alpn_protocols = &.{ "h3", "h2", "http/1.1" } };
    }

    pub fn insecureWithH3(allocator: Allocator) TLSConfig {
        return .{ .allocator = allocator, .alpn_protocols = &.{ "h3", "h2", "http/1.1" }, .verify_server = false };
    }

    pub fn wantsHTTP2(self: TLSConfig) bool {
        for (self.alpn_protocols) |proto| {
            if (mem.eql(u8, proto, "h2")) return true;
        }
        return false;
    }
};
pub const TlsConfig = TLSConfig;

pub const TLSSession = struct {
    config: TLSConfig,
    negotiated_alpn: alpn.NegotiatedAlpn = .{},
    tls_version: ?tls.ProtocolVersion = null,
    socket: ?*Socket = null,
    cipher_suite: ?tls.CipherSuite = null,
    reconnect_fn: ?*const fn (ctx: ?*anyopaque) ?*Socket = null,
    reconnect_ctx: ?*anyopaque = null,
    stored_client: ?TlsClient = null,
    hs_read_buf: [TlsClient.min_buffer_len]u8 = undefined,
    hs_write_buf: [TlsClient.min_buffer_len]u8 = undefined,
    hs_write_key: ?[32]u8 = null,
    hs_write_iv: ?[12]u8 = null,
    hs_write_seq: u64 = 0,
    hs_read_key: ?[32]u8 = null,
    hs_read_iv: ?[12]u8 = null,
    hs_read_seq: u64 = 0,
    app_write_key: ?[32]u8 = null,
    app_write_iv: ?[12]u8 = null,
    app_write_secret: ?[48]u8 = null,
    app_read_key: ?[32]u8 = null,
    app_read_iv: ?[12]u8 = null,
    app_read_secret: ?[48]u8 = null,
    write_seq: u64 = 0,
    read_seq: u64 = 0,
    read_buf: [max_record_len]u8 = undefined,
    read_buf_len: usize = 0,
    read_buf_pos: usize = 0,
    encrypted_buf: [max_record_len]u8 = undefined,
    encrypted_buf_len: usize = 0,
    encrypted_buf_pos: usize = 0,
    post_handshake_buf: [max_post_handshake_buffer_len]u8 = undefined,
    post_handshake_len: usize = 0,

    pub fn negotiatedProtocol(self: *const TLSSession) ?[]const u8 {
        return self.negotiated_alpn.get();
    }

    pub fn init(config: TLSConfig) TLSSession {
        return .{ .config = config };
    }

    pub fn deinit(self: *TLSSession) void {
        if (self.app_write_key) |*k| @memset(k, 0);
        if (self.app_write_iv) |*k| @memset(k, 0);
        if (self.app_write_secret) |*k| @memset(k, 0);
        if (self.app_read_key) |*k| @memset(k, 0);
        if (self.app_read_iv) |*k| @memset(k, 0);
        if (self.app_read_secret) |*k| @memset(k, 0);
        self.read_buf_len = 0;
        self.read_buf_pos = 0;
        self.encrypted_buf_len = 0;
        self.encrypted_buf_pos = 0;
        self.post_handshake_len = 0;
    }

    pub fn attachSocket(self: *TLSSession, socket: *Socket) void {
        self.socket = socket;
    }

    pub fn handshake(self: *TLSSession, host: []const u8) !void {
        return self.handshakeInternal(host, null);
    }

    pub fn handshakeWithContext(self: *TLSSession, host: []const u8, context: *const IoContext) !void {
        self.handshakeInternal(host, context) catch |err| {
            try context.check();
            return err;
        };
        try context.check();
    }

    fn handshakeInternal(self: *TLSSession, host: []const u8, context: ?*const IoContext) !void {
        const socket = self.socket orelse return error.TlsMissingTransport;
        self.handshakeDo(socket, host, context) catch {
            if (context) |io_context| try io_context.check();
            if (self.reconnect_fn) |reconnect| {
                if (reconnect(self.reconnect_ctx)) |new_socket| {
                    self.socket = new_socket;
                    try self.handshakeRetry(new_socket, host, context);
                    return;
                }
            }
            try self.handshakeRetry(socket, host, context);
        };
    }

    fn handshakeDo(self: *TLSSession, socket: *Socket, host: []const u8, context: ?*const IoContext) !void {
        self.encrypted_buf_len = 0;
        self.encrypted_buf_pos = 0;
        var io_reader = if (context) |io_context|
            SocketIoReader.initWithContext(socket, &self.hs_read_buf, io_context)
        else
            SocketIoReader.init(socket, &self.hs_read_buf);
        var io_writer = if (context) |io_context|
            SocketIoWriter.initWithContext(socket, &self.hs_write_buf, io_context)
        else
            SocketIoWriter.init(socket, &self.hs_write_buf);

        var entropy: [TlsClient.Options.entropy_len]u8 = undefined;
        std.Io.Threaded.global_single_threaded.io().random(&entropy);

        self.stored_client = try TlsClient.init(&io_reader.reader, &io_writer.writer, .{
            .host = if (self.config.verify_server)
                .{ .explicit = host }
            else
                .no_verification,
            .ca = if (self.config.verify_server)
                .self_signed
            else
                .no_verification,
            .write_buffer = &self.hs_write_buf,
            .read_buffer = &self.hs_read_buf,
            .entropy = &entropy,
            .realtime_now = std.Io.Timestamp.now(std.Io.Threaded.global_single_threaded.io(), .real),
            .alpn_protocols = self.config.alpn_protocols,
        });
        defer self.stored_client = null;
        self.tls_version = self.stored_client.?.tls_version;

        self.cipher_suite = switch (self.stored_client.?.tls_version) {
            .tls_1_3 => switch (self.stored_client.?.application_cipher) {
                .AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
                .AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
                .CHACHA20_POLY1305_SHA256 => .CHACHA20_POLY1305_SHA256,
                .AEGIS_256_SHA512, .AEGIS_128L_SHA256 => return error.TlsUnsupportedCipherSuite,
            },
            .tls_1_2 => switch (self.stored_client.?.application_cipher) {
                .AES_128_GCM_SHA256 => .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                .AES_256_GCM_SHA384 => .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                .CHACHA20_POLY1305_SHA256 => .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                .AEGIS_256_SHA512, .AEGIS_128L_SHA256 => return error.TlsUnsupportedCipherSuite,
            },
            else => return error.TlsUnsupportedCipherSuite,
        };

        switch (self.stored_client.?.tls_version) {
            .tls_1_3 => {
                switch (self.stored_client.?.application_cipher) {
                    inline else => |*p| {
                        const pv = &p.tls_1_3;
                        self.app_write_key = .{0} ** 32;
                        self.app_write_iv = .{0} ** 12;
                        self.app_write_secret = .{0} ** 48;
                        self.app_read_key = .{0} ** 32;
                        self.app_read_iv = .{0} ** 12;
                        self.app_read_secret = .{0} ** 48;
                        const wk = &self.app_write_key.?;
                        const wi = &self.app_write_iv.?;
                        const ws = &self.app_write_secret.?;
                        const rk = &self.app_read_key.?;
                        const ri = &self.app_read_iv.?;
                        const rs = &self.app_read_secret.?;
                        const key_len = @min(pv.client_key.len, 32);
                        const iv_len = @min(pv.client_iv.len, 12);
                        const write_secret_len = @min(pv.client_secret.len, ws.len);
                        const read_secret_len = @min(pv.server_secret.len, rs.len);
                        if (write_secret_len != pv.client_secret.len or read_secret_len != pv.server_secret.len) {
                            return error.TlsUnsupportedCipherSuite;
                        }
                        @memcpy(wk[0..key_len], pv.client_key[0..key_len]);
                        @memcpy(wi[0..iv_len], pv.client_iv[0..iv_len]);
                        @memcpy(ws[0..write_secret_len], pv.client_secret[0..write_secret_len]);
                        @memcpy(rk[0..key_len], pv.server_key[0..key_len]);
                        @memcpy(ri[0..iv_len], pv.server_iv[0..iv_len]);
                        @memcpy(rs[0..read_secret_len], pv.server_secret[0..read_secret_len]);
                    },
                }
            },
            .tls_1_2 => {
                self.app_write_secret = null;
                self.app_read_secret = null;
                switch (self.stored_client.?.application_cipher) {
                    inline else => |*p| {
                        const pv = &p.tls_1_2;
                        self.app_write_key = .{0} ** 32;
                        self.app_write_iv = .{0} ** 12;
                        self.app_read_key = .{0} ** 32;
                        self.app_read_iv = .{0} ** 12;
                        const wk = &self.app_write_key.?;
                        const wi = &self.app_write_iv.?;
                        const rk = &self.app_read_key.?;
                        const ri = &self.app_read_iv.?;
                        const key_len = @min(pv.client_write_key.len, 32);
                        const iv_len = @min(pv.client_write_IV.len, 12);
                        @memcpy(wk[0..key_len], pv.client_write_key[0..key_len]);
                        @memcpy(wi[0..iv_len], pv.client_write_IV[0..iv_len]);
                        @memcpy(rk[0..key_len], pv.server_write_key[0..key_len]);
                        @memcpy(ri[0..iv_len], pv.server_write_IV[0..iv_len]);
                    },
                }
            },
            else => return error.TlsUnsupportedCipherSuite,
        }

        if (self.stored_client.?.negotiated_alpn) |alpn_data| {
            const len = self.stored_client.?.negotiated_alpn_len;
            if (len > 0) {
                self.negotiated_alpn.set(alpn_data[0..len]);
            }
        }
        self.write_seq = self.stored_client.?.write_seq;
        self.read_seq = self.stored_client.?.read_seq;

        const buffered_encrypted = io_reader.reader.buffered();
        if (buffered_encrypted.len > self.encrypted_buf.len) {
            return error.TlsRecordOverflow;
        }
        @memcpy(self.encrypted_buf[0..buffered_encrypted.len], buffered_encrypted);
        self.encrypted_buf_len = buffered_encrypted.len;
    }

    fn handshakeRetry(self: *TLSSession, socket: *Socket, host: []const u8, context: ?*const IoContext) !void {
        try self.handshakeDo(socket, host, context);
    }

    pub fn isHTTP2(self: *const TLSSession) bool {
        return self.negotiated_alpn.isHTTP2Result();
    }

    pub fn isHTTP3(self: *const TLSSession) bool {
        return self.negotiated_alpn.isHTTP3Result();
    }

    /// Sends at most one TLS application-data record.
    pub fn write(self: *TLSSession, data: []const u8) !usize {
        const socket = self.socket orelse return 0;
        const version = self.tls_version orelse return error.TlsHandshakeNotComplete;
        const key = self.app_write_key orelse return error.TlsHandshakeNotComplete;
        const iv = self.app_write_iv orelse return error.TlsHandshakeNotComplete;
        const cs = self.cipher_suite orelse return error.TlsHandshakeNotComplete;
        return writeBoundedEncryptedRecord(socket, version, key, iv, cs, &self.write_seq, data, .application_data);
    }

    pub fn writeWithContext(self: *TLSSession, data: []const u8, context: *const IoContext) !usize {
        const socket = self.socket orelse return 0;
        const version = self.tls_version orelse return error.TlsHandshakeNotComplete;
        const key = self.app_write_key orelse return error.TlsHandshakeNotComplete;
        const iv = self.app_write_iv orelse return error.TlsHandshakeNotComplete;
        const cs = self.cipher_suite orelse return error.TlsHandshakeNotComplete;
        var sender = ContextSocketSender{ .socket = socket, .context = context };
        return writeBoundedEncryptedRecord(&sender, version, key, iv, cs, &self.write_seq, data, .application_data) catch |err| {
            try context.check();
            return err;
        };
    }

    pub fn flush(_: *TLSSession) !void {}

    /// Sends the complete application buffer as independently framed records.
    pub fn writeAll(self: *TLSSession, data: []const u8) !void {
        return writeAllBoundedRecords(self, data);
    }

    pub fn writeAllWithContext(self: *TLSSession, data: []const u8, context: *const IoContext) !void {
        var written: usize = 0;
        while (written < data.len) {
            const n = try self.writeWithContext(data[written..], context);
            if (n == 0 or n > data.len - written) return error.WriteFailed;
            written += n;
        }
    }

    pub fn read(self: *TLSSession, buf: []u8) !usize {
        return self.readInternal(buf, null);
    }

    pub fn readWithContext(self: *TLSSession, buf: []u8, context: *const IoContext) !usize {
        return self.readInternal(buf, context);
    }

    fn readInternal(self: *TLSSession, buf: []u8, context: ?*const IoContext) !usize {
        const socket = self.socket orelse return 0;
        const version = self.tls_version orelse return error.TlsHandshakeNotComplete;
        const cs = self.cipher_suite orelse return error.TlsHandshakeNotComplete;
        var state = ApplicationReadState{
            .socket = socket,
            .context = context,
            .version = version,
            .is_server = false,
            .cipher_suite = cs,
            .app_write_key = &self.app_write_key,
            .app_write_iv = &self.app_write_iv,
            .app_write_secret = &self.app_write_secret,
            .app_read_key = &self.app_read_key,
            .app_read_iv = &self.app_read_iv,
            .app_read_secret = &self.app_read_secret,
            .write_seq = &self.write_seq,
            .read_seq = &self.read_seq,
            .read_buf = &self.read_buf,
            .read_buf_len = &self.read_buf_len,
            .read_buf_pos = &self.read_buf_pos,
            .encrypted_buf = &self.encrypted_buf,
            .encrypted_buf_len = &self.encrypted_buf_len,
            .encrypted_buf_pos = &self.encrypted_buf_pos,
            .post_handshake_buf = &self.post_handshake_buf,
            .post_handshake_len = &self.post_handshake_len,
        };
        return readApplicationData(&state, buf);
    }
};
pub const TlsSession = TLSSession;

pub fn connectClient(
    allocator: Allocator,
    socket: *Socket,
    config: *const TLSConfig,
    host: []const u8,
) !Connection {
    var conn = Connection{
        .allocator = allocator,
        .socket = socket,
        .is_server = false,
        .connected = true,
    };

    var session = TLSSession.init(config.*);
    session.socket = socket;
    try session.handshake(host);

    conn.tls_version = session.tls_version orelse .tls_1_2;
    conn.app_write_key = session.app_write_key;
    conn.app_write_iv = session.app_write_iv;
    conn.app_write_secret = session.app_write_secret;
    conn.app_read_key = session.app_read_key;
    conn.app_read_iv = session.app_read_iv;
    conn.app_read_secret = session.app_read_secret;
    conn.negotiated_alpn = session.negotiated_alpn;
    conn.cipher_suite = session.cipher_suite;
    conn.write_seq = session.write_seq;
    conn.read_seq = session.read_seq;
    conn.encrypted_buf_len = session.encrypted_buf_len;
    conn.encrypted_buf_pos = session.encrypted_buf_pos;
    @memcpy(
        conn.encrypted_buf[0..session.encrypted_buf_len],
        session.encrypted_buf[0..session.encrypted_buf_len],
    );

    return conn;
}

fn detectTLS13(client_hello: []const u8) bool {
    if (client_hello.len < 42) return false;
    var off: usize = 4 + 2 + 32;
    if (off >= client_hello.len) return false;
    const session_id_len = client_hello[off];
    off += 1 + session_id_len;
    if (off + 2 > client_hello.len) return false;
    const cs_len = mem.readInt(u16, client_hello[off..][0..2], .big);
    off += 2 + cs_len;
    if (off >= client_hello.len) return false;
    const comp_len = client_hello[off];
    off += 1 + comp_len;
    if (off + 2 > client_hello.len) return false;
    const ext_len = mem.readInt(u16, client_hello[off..][0..2], .big);
    off += 2;
    const ext_end = @min(off + ext_len, client_hello.len);
    while (off + 4 <= ext_end) {
        const ext_type = mem.readInt(u16, client_hello[off..][0..2], .big);
        const ext_data_len = mem.readInt(u16, client_hello[off + 2 ..][0..2], .big);
        off += 4;
        if (ext_type == @intFromEnum(tls.ExtensionType.supported_versions)) {
            var voff: usize = off;
            if (voff + 1 <= ext_end) {
                _ = client_hello[voff];
                voff += 1;
                while (voff + 2 <= off + ext_data_len) {
                    const ver = mem.readInt(u16, client_hello[voff..][0..2], .big);
                    if (ver == @intFromEnum(tls.ProtocolVersion.tls_1_3)) return true;
                    voff += 2;
                }
            }
        }
        off += ext_data_len;
    }
    return false;
}

test "TLSConfig withH2 sets correct ALPN" {
    const config = TLSConfig.withH2(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), config.alpn_protocols.len);
    try std.testing.expectEqualStrings("h2", config.alpn_protocols[0]);
    try std.testing.expectEqualStrings("http/1.1", config.alpn_protocols[1]);
}

test "TLSConfig insecure disables verification" {
    const config = TLSConfig.insecure(std.testing.allocator);
    try std.testing.expect(!config.verify_server);
}

test "TLSSession init" {
    const session = TLSSession.init(TLSConfig.init(std.testing.allocator));
    try std.testing.expect(session.negotiated_alpn.get() == null);
    try std.testing.expect(session.tls_version == null);
}

test "TLSConfig withH3 sets correct ALPN" {
    const config = TLSConfig.withH3(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), config.alpn_protocols.len);
    try std.testing.expectEqualStrings("h3", config.alpn_protocols[0]);
    try std.testing.expectEqualStrings("h2", config.alpn_protocols[1]);
    try std.testing.expectEqualStrings("http/1.1", config.alpn_protocols[2]);
}

test "TLSConfig insecureWithH2" {
    const config = TLSConfig.insecureWithH2(std.testing.allocator);
    try std.testing.expect(!config.verify_server);
    try std.testing.expectEqual(@as(usize, 2), config.alpn_protocols.len);
}

test "TLSConfig insecureWithH3" {
    const config = TLSConfig.insecureWithH3(std.testing.allocator);
    try std.testing.expect(!config.verify_server);
    try std.testing.expectEqual(@as(usize, 3), config.alpn_protocols.len);
    try std.testing.expectEqualStrings("h3", config.alpn_protocols[0]);
}

test "TLSConfig init defaults" {
    const config = TLSConfig.init(std.testing.allocator);
    try std.testing.expect(config.verify_server);
    try std.testing.expectEqual(@as(usize, 1), config.alpn_protocols.len);
    try std.testing.expectEqualStrings("http/1.1", config.alpn_protocols[0]);
}

test "detectTLS13 returns false for short data" {
    try std.testing.expect(!detectTLS13(&[_]u8{0}));
}

test "detectTLS13 returns false for no supported_versions extension" {
    var buf: [50]u8 = [_]u8{0} ** 50;
    buf[0] = 1;
    buf[1] = 0x33;
    try std.testing.expect(!detectTLS13(&buf));
}

test "TLSSession isHTTP2/isHTTP3" {
    var session = TLSSession.init(TLSConfig.init(std.testing.allocator));
    try std.testing.expect(!session.isHTTP2());
    try std.testing.expect(!session.isHTTP3());
    session.negotiated_alpn.set("h2");
    try std.testing.expect(session.isHTTP2());
    try std.testing.expect(!session.isHTTP3());
}

test "TLSSession negotiatedProtocol returns null initially" {
    const session = TLSSession.init(TLSConfig.init(std.testing.allocator));
    try std.testing.expect(session.negotiatedProtocol() == null);
}

test "TLSSession negotiatedProtocol returns protocol after set" {
    var session = TLSSession.init(TLSConfig.init(std.testing.allocator));
    session.negotiated_alpn.set("h3");
    const proto = session.negotiatedProtocol();
    try std.testing.expect(proto != null);
    try std.testing.expectEqualStrings("h3", proto.?);
}

test "TLSSession deinit zeros key material" {
    var session = TLSSession.init(TLSConfig.init(std.testing.allocator));
    session.app_write_key = [_]u8{0xAB} ** 32;
    session.app_read_key = [_]u8{0xCD} ** 32;
    session.app_write_secret = [_]u8{0x12} ** 48;
    session.app_read_secret = [_]u8{0x34} ** 48;
    session.post_handshake_len = 7;
    session.deinit();
    if (session.app_write_key) |k| {
        for (k) |b| try std.testing.expectEqual(@as(u8, 0), b);
    }
    if (session.app_read_key) |k| {
        for (k) |b| try std.testing.expectEqual(@as(u8, 0), b);
    }
    if (session.app_write_secret) |secret| {
        for (secret) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    }
    if (session.app_read_secret) |secret| {
        for (secret) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    }
    try std.testing.expectEqual(@as(usize, 0), session.post_handshake_len);
}

test "Connection struct field defaults" {
    const defaults = Connection{
        .allocator = undefined,
        .socket = undefined,
    };
    try std.testing.expect(!defaults.is_server);
    try std.testing.expect(!defaults.connected);
    try std.testing.expect(defaults.tls_version == .tls_1_2);
    try std.testing.expect(defaults.negotiated_alpn.get() == null);
    try std.testing.expect(defaults.sni_hostname == null);
}

test "Connection sniHostname returns hostname when set" {
    const conn = Connection{
        .allocator = undefined,
        .socket = undefined,
        .sni_hostname = "example.com",
    };
    try std.testing.expect(conn.sniHostname() != null);
    try std.testing.expectEqualStrings("example.com", conn.sniHostname().?);
}

test "Connection sniHostname returns null when not set" {
    const conn = Connection{
        .allocator = undefined,
        .socket = undefined,
    };
    try std.testing.expect(conn.sniHostname() == null);
}

test "TLSConfig wantsHTTP2" {
    const config_h2 = TLSConfig.withH2(std.testing.allocator);
    try std.testing.expect(config_h2.wantsHTTP2());
    const config_default = TLSConfig.init(std.testing.allocator);
    try std.testing.expect(!config_default.wantsHTTP2());
    const config_h3 = TLSConfig.withH3(std.testing.allocator);
    try std.testing.expect(config_h3.wantsHTTP2());
}

test "nonceTLS13 XORs IV correctly" {
    const iv = [_]u8{0} ** 12;
    const nonce_val = nonceTLS13(&iv, 1);
    try std.testing.expectEqual(@as(u8, 0), nonce_val[0]);
    try std.testing.expectEqual(@as(u8, 0), nonce_val[7]);
    try std.testing.expectEqual(@as(u8, 1), nonce_val[11]);
}

test "RecordHeader format/parse round-trip" {
    var hdr_buf: [record_header_len]u8 = undefined;
    const hdr = RecordHeader{
        .content_type = .handshake,
        .version = .tls_1_2,
        .length = 256,
    };
    hdr.format(&hdr_buf);
    try std.testing.expectEqual(@intFromEnum(ContentType.handshake), hdr_buf[0]);
    try std.testing.expectEqual(@as(u16, 256), mem.readInt(u16, hdr_buf[3..5], .big));
}

const test_write_key = [_]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
const test_write_iv = [_]u8{
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
};

const TestWritePath = enum {
    connection,
    session,
};

fn testCipherSuite(path: TestWritePath, version: tls.ProtocolVersion) tls.CipherSuite {
    return switch (version) {
        .tls_1_3 => .AES_128_GCM_SHA256,
        .tls_1_2 => switch (path) {
            .connection => .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .session => .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
        else => unreachable,
    };
}

fn testRecordWireLen(version: tls.ProtocolVersion, plaintext_len: usize) usize {
    return record_header_len + switch (version) {
        .tls_1_3 => plaintext_len + 1 + crypto.aead.aes_gcm.Aes128Gcm.tag_length,
        .tls_1_2 => 8 + plaintext_len + crypto.aead.aes_gcm.Aes128Gcm.tag_length,
        else => unreachable,
    };
}

fn testExpectedWireLen(version: tls.ProtocolVersion, plaintext_len: usize) usize {
    var remaining = plaintext_len;
    var total: usize = 0;
    while (remaining > 0) {
        const chunk_len = @min(remaining, max_plaintext_len);
        total += testRecordWireLen(version, chunk_len);
        remaining -= chunk_len;
    }
    return total;
}

fn fillTestPlaintext(data: []u8) void {
    for (data, 0..) |*byte, i| {
        byte.* = @truncate((i * 37 + 11) % 251);
    }
}

fn expectApplicationRecords(
    wire: []u8,
    version: tls.ProtocolVersion,
    expected_plaintext: []const u8,
) !usize {
    var reconstructed = std.ArrayList(u8).empty;
    defer reconstructed.deinit(std.testing.allocator);

    var wire_offset: usize = 0;
    var plaintext_offset: usize = 0;
    var seq: u64 = 0;
    while (wire_offset < wire.len) : (seq += 1) {
        try std.testing.expect(wire.len - wire_offset >= record_header_len);
        const header = wire[wire_offset..][0..record_header_len];
        const record_len = mem.readInt(u16, header[3..5], .big);
        const chunk_len = @min(expected_plaintext.len - plaintext_offset, max_plaintext_len);
        const expected_record_len: usize = switch (version) {
            .tls_1_3 => chunk_len + 1 + crypto.aead.aes_gcm.Aes128Gcm.tag_length,
            .tls_1_2 => 8 + chunk_len + crypto.aead.aes_gcm.Aes128Gcm.tag_length,
            else => unreachable,
        };

        try std.testing.expectEqual(expected_record_len, record_len);
        try std.testing.expect(wire.len - wire_offset >= record_header_len + record_len);
        const record_body = wire[wire_offset + record_header_len ..][0..record_len];
        var key: [crypto.aead.aes_gcm.Aes128Gcm.key_length]u8 = undefined;
        @memcpy(&key, test_write_key[0..key.len]);

        switch (version) {
            .tls_1_3 => {
                try std.testing.expectEqual(@intFromEnum(ContentType.application_data), header[0]);
                const nonce = nonceTLS13(&test_write_iv, seq);
                const plaintext = try decryptTLS13(
                    crypto.aead.aes_gcm.Aes128Gcm,
                    record_body,
                    header,
                    &nonce,
                    &key,
                );
                try std.testing.expectEqual(chunk_len + 1, plaintext.len);
                try std.testing.expectEqual(@intFromEnum(ContentType.application_data), plaintext[plaintext.len - 1]);
                try reconstructed.appendSlice(std.testing.allocator, plaintext[0 .. plaintext.len - 1]);
            },
            .tls_1_2 => {
                try std.testing.expectEqual(@intFromEnum(ContentType.application_data), header[0]);
                const plaintext = try decryptTLS12(
                    crypto.aead.aes_gcm.Aes128Gcm,
                    record_body,
                    header,
                    seq,
                    &test_write_iv,
                    &key,
                );
                try std.testing.expectEqual(chunk_len, plaintext.len);
                try reconstructed.appendSlice(std.testing.allocator, plaintext);
            },
            else => unreachable,
        }

        plaintext_offset += chunk_len;
        wire_offset += record_header_len + record_len;
    }

    try std.testing.expectEqual(expected_plaintext.len, plaintext_offset);
    try std.testing.expectEqualSlices(u8, expected_plaintext, reconstructed.items);
    return seq;
}

fn testSocketPair() ![2]Socket {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var handles: [2]std.posix.socket_t = undefined;
        const rc = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &handles);
        if (std.posix.errno(rc) != .SUCCESS) return error.SocketPairFailed;
        return .{
            Socket.fromHandle(handles[0]),
            Socket.fromHandle(handles[1]),
        };
    }
}

const TestApplicationReader = union(TestWritePath) {
    connection: Connection,
    session: TLSSession,

    fn init(
        path: TestWritePath,
        socket: *Socket,
        version: tls.ProtocolVersion,
        cipher_suite: tls.CipherSuite,
    ) TestApplicationReader {
        return switch (path) {
            .connection => .{ .connection = .{
                .allocator = std.testing.allocator,
                .socket = socket,
                .tls_version = version,
                .connected = true,
                .app_read_key = test_write_key,
                .app_read_iv = test_write_iv,
                .cipher_suite = cipher_suite,
            } },
            .session => blk: {
                var session = TLSSession.init(TLSConfig.insecure(std.testing.allocator));
                session.socket = socket;
                session.tls_version = version;
                session.app_read_key = test_write_key;
                session.app_read_iv = test_write_iv;
                session.cipher_suite = cipher_suite;
                break :blk .{ .session = session };
            },
        };
    }

    fn read(self: *TestApplicationReader, output: []u8) !usize {
        return switch (self.*) {
            .connection => |*connection| connection.read(output),
            .session => |*session| session.read(output),
        };
    }

    fn sequence(self: *const TestApplicationReader) u64 {
        return switch (self.*) {
            .connection => |connection| connection.read_seq,
            .session => |session| session.read_seq,
        };
    }

    fn postHandshakeLength(self: *const TestApplicationReader) usize {
        return switch (self.*) {
            .connection => |connection| connection.post_handshake_len,
            .session => |session| session.post_handshake_len,
        };
    }

    fn setEncryptedInput(self: *TestApplicationReader, encrypted: []const u8) !void {
        return switch (self.*) {
            .connection => |*connection| {
                if (encrypted.len > connection.encrypted_buf.len) return error.TestInputTooLarge;
                @memcpy(connection.encrypted_buf[0..encrypted.len], encrypted);
                connection.encrypted_buf_len = encrypted.len;
                connection.encrypted_buf_pos = 0;
            },
            .session => |*session| {
                if (encrypted.len > session.encrypted_buf.len) return error.TestInputTooLarge;
                @memcpy(session.encrypted_buf[0..encrypted.len], encrypted);
                session.encrypted_buf_len = encrypted.len;
                session.encrypted_buf_pos = 0;
            },
        };
    }

    fn write(self: *TestApplicationReader, data: []const u8) !usize {
        return switch (self.*) {
            .connection => |*connection| connection.write(data),
            .session => |*session| session.write(data),
        };
    }

    fn configureTLS13Traffic(
        self: *TestApplicationReader,
        is_server: bool,
        cipher_suite: tls.CipherSuite,
        read_secret: [48]u8,
        write_secret: [48]u8,
        write_sequence: u64,
    ) void {
        const read_keys = testTrafficKeys(cipher_suite, &read_secret);
        const write_keys = testTrafficKeys(cipher_suite, &write_secret);
        switch (self.*) {
            .connection => |*connection| {
                connection.is_server = is_server;
                connection.app_read_secret = read_secret;
                connection.app_read_key = read_keys.key;
                connection.app_read_iv = read_keys.iv;
                connection.app_write_secret = write_secret;
                connection.app_write_key = write_keys.key;
                connection.app_write_iv = write_keys.iv;
                connection.write_seq = write_sequence;
            },
            .session => |*session| {
                std.debug.assert(!is_server);
                session.app_read_secret = read_secret;
                session.app_read_key = read_keys.key;
                session.app_read_iv = read_keys.iv;
                session.app_write_secret = write_secret;
                session.app_write_key = write_keys.key;
                session.app_write_iv = write_keys.iv;
                session.write_seq = write_sequence;
            },
        }
    }

    fn trafficState(self: *const TestApplicationReader) TestTrafficState {
        return switch (self.*) {
            .connection => |connection| .{
                .read_secret = connection.app_read_secret.?,
                .read_key = connection.app_read_key.?,
                .read_iv = connection.app_read_iv.?,
                .read_seq = connection.read_seq,
                .write_secret = connection.app_write_secret.?,
                .write_key = connection.app_write_key.?,
                .write_iv = connection.app_write_iv.?,
                .write_seq = connection.write_seq,
                .post_handshake_len = connection.post_handshake_len,
            },
            .session => |session| .{
                .read_secret = session.app_read_secret.?,
                .read_key = session.app_read_key.?,
                .read_iv = session.app_read_iv.?,
                .read_seq = session.read_seq,
                .write_secret = session.app_write_secret.?,
                .write_key = session.app_write_key.?,
                .write_iv = session.app_write_iv.?,
                .write_seq = session.write_seq,
                .post_handshake_len = session.post_handshake_len,
            },
        };
    }
};

const TestTrafficState = struct {
    read_secret: [48]u8,
    read_key: [32]u8,
    read_iv: [12]u8,
    read_seq: u64,
    write_secret: [48]u8,
    write_key: [32]u8,
    write_iv: [12]u8,
    write_seq: u64,
    post_handshake_len: usize,
};

fn testReadCipherSuite(path: TestWritePath, version: tls.ProtocolVersion) tls.CipherSuite {
    return switch (version) {
        .tls_1_3 => switch (path) {
            .connection => .AES_128_GCM_SHA256,
            .session => .CHACHA20_POLY1305_SHA256,
        },
        .tls_1_2 => testCipherSuite(path, version),
        else => unreachable,
    };
}

fn testTrafficKeys(
    cipher_suite: tls.CipherSuite,
    secret: *const [48]u8,
) struct { key: [32]u8, iv: [12]u8 } {
    const secret_slice = switch (cipher_suite) {
        .AES_128_GCM_SHA256, .CHACHA20_POLY1305_SHA256 => secret[0..32],
        .AES_256_GCM_SHA384 => secret[0..48],
        else => unreachable,
    };
    const keys = deriveTrafficKeys13(secret_slice);
    var key: [32]u8 = .{0} ** 32;
    if (cipher_suite == .AES_128_GCM_SHA256) {
        @memcpy(key[0..keys.key16.len], &keys.key16);
    } else {
        key = keys.key32;
    }
    return .{ .key = key, .iv = keys.iv };
}

fn appendTestProtectedRecordWithKeys(
    wire: *std.ArrayList(u8),
    version: tls.ProtocolVersion,
    cipher_suite: tls.CipherSuite,
    key_bytes: [32]u8,
    iv_bytes: [12]u8,
    sequence: u64,
    content: []const u8,
    content_type: u8,
    tls13_padding_len: usize,
    include_tls13_content_type: bool,
) !void {
    var header: [record_header_len]u8 = undefined;
    header[1] = 0x03;
    header[2] = 0x03;
    var encrypted_buf: [max_ciphertext_len]u8 = undefined;

    const encrypted = switch (version) {
        .tls_1_3 => blk: {
            var inner: [max_ciphertext_len]u8 = undefined;
            const type_len: usize = if (include_tls13_content_type) 1 else 0;
            const inner_len = content.len + type_len + tls13_padding_len;
            if (inner_len > inner.len - crypto.aead.aes_gcm.Aes128Gcm.tag_length) {
                return error.TestRecordTooLarge;
            }
            @memcpy(inner[0..content.len], content);
            var inner_pos = content.len;
            if (include_tls13_content_type) {
                inner[inner_pos] = content_type;
                inner_pos += 1;
            }
            @memset(inner[inner_pos..inner_len], 0);

            header[0] = @intFromEnum(ContentType.application_data);
            mem.writeInt(u16, header[3..5], @intCast(inner_len + crypto.aead.aes_gcm.Aes128Gcm.tag_length), .big);
            const nonce = nonceTLS13(&iv_bytes, sequence);
            break :blk switch (cipher_suite) {
                .AES_128_GCM_SHA256 => aes128: {
                    var key: [16]u8 = undefined;
                    @memcpy(&key, key_bytes[0..key.len]);
                    break :aes128 try encryptTLS13(
                        crypto.aead.aes_gcm.Aes128Gcm,
                        &encrypted_buf,
                        inner[0..inner_len],
                        &header,
                        &nonce,
                        &key,
                    );
                },
                .AES_256_GCM_SHA384 => try encryptTLS13(
                    crypto.aead.aes_gcm.Aes256Gcm,
                    &encrypted_buf,
                    inner[0..inner_len],
                    &header,
                    &nonce,
                    &key_bytes,
                ),
                .CHACHA20_POLY1305_SHA256 => try encryptTLS13(
                    crypto.aead.chacha_poly.ChaCha20Poly1305,
                    &encrypted_buf,
                    inner[0..inner_len],
                    &header,
                    &nonce,
                    &key_bytes,
                ),
                else => return error.TlsUnsupportedCipherSuite,
            };
        },
        .tls_1_2 => blk: {
            if (tls13_padding_len != 0 or !include_tls13_content_type) {
                return error.InvalidTestRecord;
            }
            header[0] = content_type;
            mem.writeInt(
                u16,
                header[3..5],
                @intCast(try tls12CiphertextLen(cipher_suite, content.len)),
                .big,
            );
            break :blk try encryptTLS12ForSuite(
                &encrypted_buf,
                content,
                &header,
                sequence,
                &iv_bytes,
                &key_bytes,
                cipher_suite,
            );
        },
        else => return error.TlsUnsupportedCipherSuite,
    };

    try wire.appendSlice(std.testing.allocator, &header);
    try wire.appendSlice(std.testing.allocator, encrypted);
}

fn appendTestProtectedRecord(
    wire: *std.ArrayList(u8),
    version: tls.ProtocolVersion,
    cipher_suite: tls.CipherSuite,
    sequence: u64,
    content: []const u8,
    content_type: u8,
    tls13_padding_len: usize,
    include_tls13_content_type: bool,
) !void {
    return appendTestProtectedRecordWithKeys(
        wire,
        version,
        cipher_suite,
        test_write_key,
        test_write_iv,
        sequence,
        content,
        content_type,
        tls13_padding_len,
        include_tls13_content_type,
    );
}

fn appendTestHandshakeMessage(
    message: *std.ArrayList(u8),
    handshake_type: tls.HandshakeType,
    body: []const u8,
) !void {
    var header: [4]u8 = undefined;
    header[0] = @intFromEnum(handshake_type);
    mem.writeInt(u24, header[1..4], @intCast(body.len), .big);
    try message.appendSlice(std.testing.allocator, &header);
    try message.appendSlice(std.testing.allocator, body);
}

fn readTestTLS13Record(
    socket: *Socket,
    cipher_suite: tls.CipherSuite,
    key: [32]u8,
    iv: [12]u8,
    sequence: *u64,
    record_buf: *[4096]u8,
) !ApplicationRecord {
    const ciphertext = try readTLSRecord(socket, record_buf);
    if (record_buf[0] != @intFromEnum(ContentType.application_data)) {
        return error.TlsUnexpectedMessage;
    }
    const plaintext = try decryptTLS13ForSuite(
        @constCast(ciphertext),
        record_buf[0..record_header_len],
        sequence.*,
        &iv,
        &key,
        cipher_suite,
    );
    sequence.* += 1;
    return parseTLS13InnerPlaintext(plaintext);
}

fn makeTestTrafficSecret(cipher_suite: tls.CipherSuite, seed: u8) [48]u8 {
    const secret_len: usize = switch (cipher_suite) {
        .AES_128_GCM_SHA256, .CHACHA20_POLY1305_SHA256 => 32,
        .AES_256_GCM_SHA384 => 48,
        else => unreachable,
    };
    var secret: [48]u8 = .{0} ** 48;
    for (secret[0..secret_len], 0..) |*byte, i| {
        byte.* = seed +% @as(u8, @truncate(i * 13));
    }
    return secret;
}

fn testUpdatedTrafficSecret(
    cipher_suite: tls.CipherSuite,
    secret: *const [48]u8,
) [48]u8 {
    var updated: [48]u8 = .{0} ** 48;
    switch (cipher_suite) {
        .AES_128_GCM_SHA256, .CHACHA20_POLY1305_SHA256 => {
            updated[0..32].* = hkdfExpandLabel(secret[0..32], "traffic upd", "", 32);
        },
        .AES_256_GCM_SHA384 => {
            updated = hkdfExpandLabel(secret, "traffic upd", "", 48);
        },
        else => unreachable,
    }
    return updated;
}

fn expectProtectedRecordError(
    path: TestWritePath,
    version: tls.ProtocolVersion,
    content: []const u8,
    content_type: u8,
    tls13_padding_len: usize,
    include_tls13_content_type: bool,
    expected_error: anyerror,
) !void {
    const cipher_suite = testReadCipherSuite(path, version);
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(std.testing.allocator);
    try appendTestProtectedRecord(
        &wire,
        version,
        cipher_suite,
        0,
        content,
        content_type,
        tls13_padding_len,
        include_tls13_content_type,
    );

    const sockets = try testSocketPair();
    var sender = sockets[0];
    defer sender.close();
    var receiver = sockets[1];
    defer receiver.close();
    try sender.sendAll(wire.items);

    var reader = TestApplicationReader.init(path, &receiver, version, cipher_suite);
    var output: [64]u8 = undefined;
    try std.testing.expectError(expected_error, reader.read(&output));
    try std.testing.expectEqual(@as(u64, 1), reader.sequence());
}

const SocketReadContext = struct {
    socket: *Socket,
    buffer: []u8,
    read_len: usize = 0,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        while (self.read_len < self.buffer.len) {
            const n = self.socket.recv(self.buffer[self.read_len..]) catch |err| {
                self.err = err;
                return;
            };
            if (n == 0) {
                self.err = error.UnexpectedEof;
                return;
            }
            self.read_len += n;
        }
    }
};

const CapturedWrite = struct {
    wire: []u8,
    consumed: usize,
    sequence: u64,
};

fn captureApplicationWrite(
    allocator: Allocator,
    path: TestWritePath,
    version: tls.ProtocolVersion,
    plaintext: []const u8,
    write_all: bool,
) !CapturedWrite {
    const sockets = try testSocketPair();
    var sender = sockets[0];
    defer sender.close();
    var receiver = sockets[1];
    defer receiver.close();

    const expected_plaintext_len = if (write_all) plaintext.len else @min(plaintext.len, max_plaintext_len);
    const expected_wire_len = testExpectedWireLen(version, expected_plaintext_len);
    const wire = try allocator.alloc(u8, expected_wire_len);
    errdefer allocator.free(wire);

    var read_context = SocketReadContext{
        .socket = &receiver,
        .buffer = wire,
    };
    var read_thread: ?std.Thread = null;
    if (wire.len > 0) {
        read_thread = try std.Thread.spawn(.{}, SocketReadContext.run, .{&read_context});
    }
    errdefer {
        sender.close();
        if (read_thread) |thread| {
            thread.join();
            read_thread = null;
        }
    }

    var sequence: u64 = 0;
    const consumed = switch (path) {
        .connection => blk: {
            var conn = Connection{
                .allocator = allocator,
                .socket = &sender,
                .tls_version = version,
                .connected = true,
                .app_write_key = test_write_key,
                .app_write_iv = test_write_iv,
                .cipher_suite = testCipherSuite(path, version),
            };
            if (write_all) {
                try conn.writeAll(plaintext);
                sequence = conn.write_seq;
                break :blk plaintext.len;
            }
            const n = try conn.write(plaintext);
            sequence = conn.write_seq;
            break :blk n;
        },
        .session => blk: {
            var session = TLSSession.init(TLSConfig.insecure(allocator));
            session.socket = &sender;
            session.tls_version = version;
            session.app_write_key = test_write_key;
            session.app_write_iv = test_write_iv;
            session.cipher_suite = testCipherSuite(path, version);
            if (write_all) {
                try session.writeAll(plaintext);
                sequence = session.write_seq;
                break :blk plaintext.len;
            }
            const n = try session.write(plaintext);
            sequence = session.write_seq;
            break :blk n;
        },
    };

    if (read_thread) |thread| thread.join();
    if (read_context.err) |err| return err;
    try std.testing.expectEqual(wire.len, read_context.read_len);
    return .{
        .wire = wire,
        .consumed = consumed,
        .sequence = sequence,
    };
}

test "TLS application writes split exact record boundaries" {
    const sizes = [_]usize{ 0, 1, 16_383, 16_384, 16_385, 64 * 1024 + 123 };
    const paths = [_]TestWritePath{ .connection, .session };
    const versions = [_]tls.ProtocolVersion{ .tls_1_2, .tls_1_3 };

    for (paths) |path| {
        for (versions) |version| {
            for (sizes) |size| {
                const plaintext = try std.testing.allocator.alloc(u8, size);
                defer std.testing.allocator.free(plaintext);
                fillTestPlaintext(plaintext);

                const single = try captureApplicationWrite(
                    std.testing.allocator,
                    path,
                    version,
                    plaintext,
                    false,
                );
                defer std.testing.allocator.free(single.wire);
                const expected_consumed = @min(size, max_plaintext_len);
                try std.testing.expectEqual(expected_consumed, single.consumed);
                const single_records = try expectApplicationRecords(
                    single.wire,
                    version,
                    plaintext[0..expected_consumed],
                );
                try std.testing.expectEqual(single_records, single.sequence);
                try std.testing.expectEqual(@as(usize, if (size == 0) 0 else 1), single_records);

                const all = try captureApplicationWrite(
                    std.testing.allocator,
                    path,
                    version,
                    plaintext,
                    true,
                );
                defer std.testing.allocator.free(all.wire);
                try std.testing.expectEqual(size, all.consumed);
                const all_records = try expectApplicationRecords(all.wire, version, plaintext);
                const expected_records = if (size == 0) 0 else (size + max_plaintext_len - 1) / max_plaintext_len;
                try std.testing.expectEqual(expected_records, all_records);
                try std.testing.expectEqual(all_records, all.sequence);
            }
        }
    }
}

const ScriptedSender = struct {
    allocator: Allocator,
    bytes: std.ArrayList(u8) = .empty,
    max_chunk: usize,
    fail_after: ?usize = null,
    underlying_writes: usize = 0,

    fn deinit(self: *@This()) void {
        self.bytes.deinit(self.allocator);
    }

    fn sendAll(self: *@This(), data: []const u8) !void {
        var sent: usize = 0;
        while (sent < data.len) {
            if (self.fail_after) |limit| {
                if (self.bytes.items.len >= limit) return error.ScriptedWriteFailure;
            }

            var chunk_len = @min(self.max_chunk, data.len - sent);
            if (self.fail_after) |limit| {
                chunk_len = @min(chunk_len, limit - self.bytes.items.len);
            }
            if (chunk_len == 0) return error.ScriptedWriteFailure;

            try self.bytes.appendSlice(self.allocator, data[sent..][0..chunk_len]);
            self.underlying_writes += 1;
            sent += chunk_len;
        }
    }
};

const ScriptedRecordWriter = struct {
    sender: *ScriptedSender,
    version: tls.ProtocolVersion,
    cipher_suite: ?tls.CipherSuite = null,
    sequence: u64 = 0,

    fn write(self: *@This(), data: []const u8) !usize {
        return writeBoundedEncryptedRecord(
            self.sender,
            self.version,
            test_write_key,
            test_write_iv,
            self.cipher_suite orelse testCipherSuite(.session, self.version),
            &self.sequence,
            data,
            .application_data,
        );
    }
};

test "TLS record send-all handles partial writes and failed records" {
    const versions = [_]tls.ProtocolVersion{ .tls_1_2, .tls_1_3 };
    for (versions) |version| {
        const plaintext = try std.testing.allocator.alloc(u8, 16_385);
        defer std.testing.allocator.free(plaintext);
        fillTestPlaintext(plaintext);

        var partial_sender = ScriptedSender{
            .allocator = std.testing.allocator,
            .max_chunk = 7,
        };
        defer partial_sender.deinit();
        var partial_writer = ScriptedRecordWriter{
            .sender = &partial_sender,
            .version = version,
        };
        const consumed = try partial_writer.write(plaintext);
        try std.testing.expectEqual(@as(usize, max_plaintext_len), consumed);
        try std.testing.expect(partial_sender.underlying_writes > 1);
        try std.testing.expectEqual(@as(u64, 1), partial_writer.sequence);
        const records = try expectApplicationRecords(
            partial_sender.bytes.items,
            version,
            plaintext[0..max_plaintext_len],
        );
        try std.testing.expectEqual(@as(usize, 1), records);

        const first_record_len = testRecordWireLen(version, max_plaintext_len);
        var failing_sender = ScriptedSender{
            .allocator = std.testing.allocator,
            .max_chunk = 11,
            .fail_after = first_record_len + 7,
        };
        defer failing_sender.deinit();
        var failing_writer = ScriptedRecordWriter{
            .sender = &failing_sender,
            .version = version,
        };
        try std.testing.expectError(
            error.WriteFailed,
            writeAllBoundedRecords(&failing_writer, plaintext),
        );
        try std.testing.expectEqual(@as(u64, 1), failing_writer.sequence);
        try std.testing.expectEqual(first_record_len + 7, failing_sender.bytes.items.len);
        const completed_records = try expectApplicationRecords(
            failing_sender.bytes.items[0..first_record_len],
            version,
            plaintext[0..max_plaintext_len],
        );
        try std.testing.expectEqual(@as(usize, 1), completed_records);
    }
}

test "TLS writeAll rejects zero progress and preserves errors" {
    const ZeroProgressWriter = struct {
        fn write(_: *@This(), _: []const u8) !usize {
            return 0;
        }
    };
    var zero_writer = ZeroProgressWriter{};
    try std.testing.expectError(
        error.WriteFailed,
        writeAllBoundedRecords(&zero_writer, "data"),
    );

    const ErrorWriter = struct {
        fn write(_: *@This(), _: []const u8) !usize {
            return error.TlsHandshakeNotComplete;
        }
    };
    var error_writer = ErrorWriter{};
    try std.testing.expectError(
        error.TlsHandshakeNotComplete,
        writeAllBoundedRecords(&error_writer, "data"),
    );

    var session = TLSSession.init(TLSConfig.insecure(std.testing.allocator));
    try std.testing.expectError(error.WriteFailed, session.writeAll("data"));
}

const ApplicationWriteThreadContext = struct {
    socket: *Socket,
    path: TestWritePath,
    version: tls.ProtocolVersion,
    cipher_suite: tls.CipherSuite,
    plaintext: []const u8,
    sequence: u64 = 0,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        defer self.socket.shutdownWrite() catch {};
        switch (self.path) {
            .connection => {
                var conn = Connection{
                    .allocator = std.testing.allocator,
                    .socket = self.socket,
                    .tls_version = self.version,
                    .connected = true,
                    .app_write_key = test_write_key,
                    .app_write_iv = test_write_iv,
                    .cipher_suite = self.cipher_suite,
                };
                conn.writeAll(self.plaintext) catch |err| {
                    self.err = err;
                    return;
                };
                self.sequence = conn.write_seq;
            },
            .session => {
                var session = TLSSession.init(TLSConfig.insecure(std.testing.allocator));
                session.socket = self.socket;
                session.tls_version = self.version;
                session.app_write_key = test_write_key;
                session.app_write_iv = test_write_iv;
                session.cipher_suite = self.cipher_suite;
                session.writeAll(self.plaintext) catch |err| {
                    self.err = err;
                    return;
                };
                self.sequence = session.write_seq;
            },
        }
    }
};

fn expectApplicationRoundTrip(
    writer_path: TestWritePath,
    reader_path: TestWritePath,
    version: tls.ProtocolVersion,
    cipher_suite: tls.CipherSuite,
    plaintext: []const u8,
    read_chunk_len: usize,
) !void {
    try std.testing.expect(read_chunk_len > 0 and read_chunk_len <= 8192);
    const sockets = try testSocketPair();
    var sender = sockets[0];
    defer sender.close();
    var receiver = sockets[1];
    defer receiver.close();

    var write_context = ApplicationWriteThreadContext{
        .socket = &sender,
        .path = writer_path,
        .version = version,
        .cipher_suite = cipher_suite,
        .plaintext = plaintext,
    };
    var write_thread: ?std.Thread = try std.Thread.spawn(
        .{},
        ApplicationWriteThreadContext.run,
        .{&write_context},
    );
    errdefer {
        receiver.close();
        if (write_thread) |thread| thread.join();
    }

    var connection_reader = Connection{
        .allocator = std.testing.allocator,
        .socket = &receiver,
        .tls_version = version,
        .connected = true,
        .app_read_key = test_write_key,
        .app_read_iv = test_write_iv,
        .cipher_suite = cipher_suite,
    };
    var session_reader = TLSSession.init(TLSConfig.insecure(std.testing.allocator));
    session_reader.socket = &receiver;
    session_reader.tls_version = version;
    session_reader.app_read_key = test_write_key;
    session_reader.app_read_iv = test_write_iv;
    session_reader.cipher_suite = cipher_suite;

    var reconstructed = std.ArrayList(u8).empty;
    defer reconstructed.deinit(std.testing.allocator);
    var read_buf: [8192]u8 = undefined;
    while (reconstructed.items.len < plaintext.len) {
        const n = switch (reader_path) {
            .connection => try connection_reader.read(read_buf[0..read_chunk_len]),
            .session => try session_reader.read(read_buf[0..read_chunk_len]),
        };
        if (n == 0) return error.UnexpectedEof;
        try reconstructed.appendSlice(std.testing.allocator, read_buf[0..n]);
    }

    if (write_thread) |thread| {
        thread.join();
        write_thread = null;
    }
    if (write_context.err) |err| return err;

    const expected_records = if (plaintext.len == 0) 0 else (plaintext.len + max_plaintext_len - 1) / max_plaintext_len;
    const read_sequence = switch (reader_path) {
        .connection => connection_reader.read_seq,
        .session => session_reader.read_seq,
    };
    try std.testing.expectEqual(expected_records, write_context.sequence);
    try std.testing.expectEqual(expected_records, read_sequence);
    try std.testing.expectEqualSlices(u8, plaintext, reconstructed.items);
}

test "TLS 1.3 small reads preserve complete multi-record plaintext" {
    const plaintext = try std.testing.allocator.alloc(u8, 2 * max_plaintext_len + 123);
    defer std.testing.allocator.free(plaintext);
    fillTestPlaintext(plaintext);

    try expectApplicationRoundTrip(
        .session,
        .connection,
        .tls_1_3,
        .AES_128_GCM_SHA256,
        plaintext,
        8192,
    );
    try expectApplicationRoundTrip(
        .connection,
        .session,
        .tls_1_3,
        .AES_128_GCM_SHA256,
        plaintext,
        8192,
    );
}

test "TLS 1.3 application reads strip padding and preserve buffered plaintext" {
    const paths = [_]TestWritePath{ .connection, .session };
    const messages = [_][]const u8{ "padded ", "application data" };
    const expected = "padded application data";

    for (paths) |path| {
        const cipher_suite = testReadCipherSuite(path, .tls_1_3);
        var wire = std.ArrayList(u8).empty;
        defer wire.deinit(std.testing.allocator);
        try appendTestProtectedRecord(
            &wire,
            .tls_1_3,
            cipher_suite,
            0,
            messages[0],
            @intFromEnum(ContentType.application_data),
            7,
            true,
        );
        try appendTestProtectedRecord(
            &wire,
            .tls_1_3,
            cipher_suite,
            1,
            messages[1],
            @intFromEnum(ContentType.application_data),
            31,
            true,
        );

        const sockets = try testSocketPair();
        var sender = sockets[0];
        defer sender.close();
        var receiver = sockets[1];
        defer receiver.close();
        try sender.sendAll(wire.items);

        var reader = TestApplicationReader.init(path, &receiver, .tls_1_3, cipher_suite);
        var reconstructed: [expected.len]u8 = undefined;
        var offset: usize = 0;
        while (offset < reconstructed.len) {
            var small_buf: [3]u8 = undefined;
            const n = try reader.read(small_buf[0..@min(small_buf.len, reconstructed.len - offset)]);
            try std.testing.expect(n > 0);
            @memcpy(reconstructed[offset..][0..n], small_buf[0..n]);
            offset += n;
        }
        try std.testing.expectEqualStrings(expected, &reconstructed);
        try std.testing.expectEqual(@as(u64, 2), reader.sequence());
    }
}

test "TLS application reads dispatch authenticated alerts and unexpected content" {
    const paths = [_]TestWritePath{ .connection, .session };
    const alert_close_notify = [_]u8{ 1, @intFromEnum(tls.Alert.Description.close_notify) };
    const alert_handshake_failure = [_]u8{ 2, @intFromEnum(tls.Alert.Description.handshake_failure) };
    const unexpected_handshake = [_]u8{ @intFromEnum(tls.HandshakeType.finished), 0, 0, 0 };

    for (paths) |path| {
        try expectProtectedRecordError(
            path,
            .tls_1_3,
            &alert_close_notify,
            @intFromEnum(ContentType.alert),
            5,
            true,
            error.TlsCloseNotify,
        );
        try expectProtectedRecordError(
            path,
            .tls_1_3,
            &alert_handshake_failure,
            @intFromEnum(ContentType.alert),
            0,
            true,
            error.TlsHandshakeFailure,
        );
        try expectProtectedRecordError(
            path,
            .tls_1_3,
            &unexpected_handshake,
            @intFromEnum(ContentType.handshake),
            3,
            true,
            error.TlsUnexpectedMessage,
        );
        try expectProtectedRecordError(
            path,
            .tls_1_3,
            "",
            0,
            8,
            false,
            error.TlsUnexpectedMessage,
        );

        try expectProtectedRecordError(
            path,
            .tls_1_2,
            &alert_close_notify,
            @intFromEnum(ContentType.alert),
            0,
            true,
            error.TlsCloseNotify,
        );
        try expectProtectedRecordError(
            path,
            .tls_1_2,
            &alert_handshake_failure,
            @intFromEnum(ContentType.alert),
            0,
            true,
            error.TlsHandshakeFailure,
        );
        try expectProtectedRecordError(
            path,
            .tls_1_2,
            &unexpected_handshake,
            @intFromEnum(ContentType.handshake),
            0,
            true,
            error.TlsUnexpectedMessage,
        );
    }
}

test "TLS 1.3 clients ignore fragmented and coalesced NewSessionTicket messages" {
    const paths = [_]TestWritePath{ .connection, .session };
    const ticket_body = [_]u8{
        0, 0, 0, 60, // ticket_lifetime
        0x01, 0x02, 0x03, 0x04, // ticket_age_add
        2, 0xaa, 0xbb, // ticket_nonce
        0, 3, 't', 'k', 't', // ticket
        0, 6, // extensions length
        0, 42, 0, 2, 0x12, 0x34, // one extension
    };
    const application_data = "response after tickets";

    var first_ticket = std.ArrayList(u8).empty;
    defer first_ticket.deinit(std.testing.allocator);
    try appendTestHandshakeMessage(&first_ticket, .new_session_ticket, &ticket_body);

    var second_fragment = std.ArrayList(u8).empty;
    defer second_fragment.deinit(std.testing.allocator);
    try second_fragment.appendSlice(std.testing.allocator, first_ticket.items[2..]);
    try appendTestHandshakeMessage(&second_fragment, .new_session_ticket, &ticket_body);

    for (paths) |path| {
        const cipher_suite = testReadCipherSuite(path, .tls_1_3);
        var wire = std.ArrayList(u8).empty;
        defer wire.deinit(std.testing.allocator);
        try appendTestProtectedRecord(
            &wire,
            .tls_1_3,
            cipher_suite,
            0,
            first_ticket.items[0..2],
            @intFromEnum(ContentType.handshake),
            0,
            true,
        );
        try appendTestProtectedRecord(
            &wire,
            .tls_1_3,
            cipher_suite,
            1,
            second_fragment.items,
            @intFromEnum(ContentType.handshake),
            3,
            true,
        );
        try appendTestProtectedRecord(
            &wire,
            .tls_1_3,
            cipher_suite,
            2,
            application_data,
            @intFromEnum(ContentType.application_data),
            5,
            true,
        );

        const sockets = try testSocketPair();
        var sender = sockets[0];
        defer sender.close();
        var receiver = sockets[1];
        defer receiver.close();

        var reader = TestApplicationReader.init(path, &receiver, .tls_1_3, cipher_suite);
        if (path == .session) {
            try reader.setEncryptedInput(wire.items);
        } else {
            try sender.sendAll(wire.items);
        }
        var output: [application_data.len]u8 = undefined;
        const first_len = try reader.read(output[0..5]);
        try std.testing.expectEqual(@as(usize, 5), first_len);
        const second_len = try reader.read(output[first_len..]);
        try std.testing.expectEqual(application_data.len - first_len, second_len);
        try std.testing.expectEqualStrings(application_data, &output);
        try std.testing.expectEqual(@as(u64, 3), reader.sequence());
        try std.testing.expectEqual(@as(usize, 0), reader.postHandshakeLength());
    }
}

test "TLS 1.3 post-handshake messages enforce role and framing" {
    const paths = [_]TestWritePath{ .connection, .session };
    const malformed_ticket_body = [_]u8{
        0, 0, 0, 60,
        0, 0, 0, 1,
        0,
        0, 0, // empty ticket is forbidden
        0, 0,
    };
    var malformed_ticket = std.ArrayList(u8).empty;
    defer malformed_ticket.deinit(std.testing.allocator);
    try appendTestHandshakeMessage(&malformed_ticket, .new_session_ticket, &malformed_ticket_body);

    var empty_key_update = std.ArrayList(u8).empty;
    defer empty_key_update.deinit(std.testing.allocator);
    try appendTestHandshakeMessage(&empty_key_update, .key_update, "");

    const invalid_key_update_body = [_]u8{2};
    var invalid_key_update = std.ArrayList(u8).empty;
    defer invalid_key_update.deinit(std.testing.allocator);
    try appendTestHandshakeMessage(&invalid_key_update, .key_update, &invalid_key_update_body);

    const valid_key_update_body = [_]u8{@intFromEnum(tls.KeyUpdateRequest.update_not_requested)};
    var key_update_without_secret = std.ArrayList(u8).empty;
    defer key_update_without_secret.deinit(std.testing.allocator);
    try appendTestHandshakeMessage(&key_update_without_secret, .key_update, &valid_key_update_body);

    for (paths) |path| {
        try expectProtectedRecordError(
            path,
            .tls_1_3,
            malformed_ticket.items,
            @intFromEnum(ContentType.handshake),
            0,
            true,
            error.TlsDecodeError,
        );
        try expectProtectedRecordError(
            path,
            .tls_1_3,
            empty_key_update.items,
            @intFromEnum(ContentType.handshake),
            0,
            true,
            error.TlsDecodeError,
        );
        try expectProtectedRecordError(
            path,
            .tls_1_3,
            invalid_key_update.items,
            @intFromEnum(ContentType.handshake),
            0,
            true,
            error.TlsIllegalParameter,
        );
        try expectProtectedRecordError(
            path,
            .tls_1_3,
            key_update_without_secret.items,
            @intFromEnum(ContentType.handshake),
            0,
            true,
            error.TlsHandshakeNotComplete,
        );
    }

    const valid_ticket_body = [_]u8{
        0, 0, 0, 60,
        0, 0, 0, 1,
        0, 0, 1, 0xaa,
        0, 0,
    };
    var valid_ticket = std.ArrayList(u8).empty;
    defer valid_ticket.deinit(std.testing.allocator);
    try appendTestHandshakeMessage(&valid_ticket, .new_session_ticket, &valid_ticket_body);

    const cipher_suite = testReadCipherSuite(.connection, .tls_1_3);
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(std.testing.allocator);
    try appendTestProtectedRecord(
        &wire,
        .tls_1_3,
        cipher_suite,
        0,
        valid_ticket.items,
        @intFromEnum(ContentType.handshake),
        0,
        true,
    );
    const sockets = try testSocketPair();
    var sender = sockets[0];
    defer sender.close();
    var receiver = sockets[1];
    defer receiver.close();
    try sender.sendAll(wire.items);

    var server_reader = Connection{
        .allocator = std.testing.allocator,
        .socket = &receiver,
        .tls_version = .tls_1_3,
        .is_server = true,
        .connected = true,
        .app_read_key = test_write_key,
        .app_read_iv = test_write_iv,
        .cipher_suite = cipher_suite,
    };
    var output: [1]u8 = undefined;
    try std.testing.expectError(error.TlsUnexpectedMessage, server_reader.read(&output));
    try std.testing.expectEqual(@as(u64, 1), server_reader.read_seq);
}

test "TLS 1.3 KeyUpdate rotates traffic state and preserves application data" {
    const cases = [_]struct {
        path: TestWritePath,
        is_server: bool,
        cipher_suite: tls.CipherSuite,
    }{
        .{ .path = .connection, .is_server = false, .cipher_suite = .AES_128_GCM_SHA256 },
        .{ .path = .session, .is_server = false, .cipher_suite = .CHACHA20_POLY1305_SHA256 },
        .{ .path = .connection, .is_server = true, .cipher_suite = .AES_256_GCM_SHA384 },
    };
    const requests = [_]tls.KeyUpdateRequest{ .update_not_requested, .update_requested };
    const inbound_application_data = "inbound after key update";
    const outbound_application_data = "outbound after key update";
    const initial_write_sequence: u64 = 7;

    for (cases) |case| {
        for (requests) |request| {
            const initial_read_secret = makeTestTrafficSecret(case.cipher_suite, 0x21);
            const initial_write_secret = makeTestTrafficSecret(case.cipher_suite, 0x91);
            const initial_read_keys = testTrafficKeys(case.cipher_suite, &initial_read_secret);
            const initial_write_keys = testTrafficKeys(case.cipher_suite, &initial_write_secret);

            const updated_read_secret = testUpdatedTrafficSecret(
                case.cipher_suite,
                &initial_read_secret,
            );
            const updated_read_keys = testTrafficKeys(case.cipher_suite, &updated_read_secret);

            var key_update = std.ArrayList(u8).empty;
            defer key_update.deinit(std.testing.allocator);
            const request_body = [_]u8{@intFromEnum(request)};
            try appendTestHandshakeMessage(&key_update, .key_update, &request_body);

            var wire = std.ArrayList(u8).empty;
            defer wire.deinit(std.testing.allocator);
            const fragment_key_update = case.is_server and request == .update_requested;
            if (fragment_key_update) {
                try appendTestProtectedRecordWithKeys(
                    &wire,
                    .tls_1_3,
                    case.cipher_suite,
                    initial_read_keys.key,
                    initial_read_keys.iv,
                    0,
                    key_update.items[0..2],
                    @intFromEnum(ContentType.handshake),
                    0,
                    true,
                );
                try appendTestProtectedRecordWithKeys(
                    &wire,
                    .tls_1_3,
                    case.cipher_suite,
                    initial_read_keys.key,
                    initial_read_keys.iv,
                    1,
                    key_update.items[2..],
                    @intFromEnum(ContentType.handshake),
                    0,
                    true,
                );
            } else {
                try appendTestProtectedRecordWithKeys(
                    &wire,
                    .tls_1_3,
                    case.cipher_suite,
                    initial_read_keys.key,
                    initial_read_keys.iv,
                    0,
                    key_update.items,
                    @intFromEnum(ContentType.handshake),
                    0,
                    true,
                );
            }
            try appendTestProtectedRecordWithKeys(
                &wire,
                .tls_1_3,
                case.cipher_suite,
                updated_read_keys.key,
                updated_read_keys.iv,
                0,
                inbound_application_data,
                @intFromEnum(ContentType.application_data),
                2,
                true,
            );

            const sockets = try testSocketPair();
            var peer = sockets[0];
            defer peer.close();
            var local = sockets[1];
            defer local.close();
            try peer.sendAll(wire.items);

            var reader = TestApplicationReader.init(case.path, &local, .tls_1_3, case.cipher_suite);
            reader.configureTLS13Traffic(
                case.is_server,
                case.cipher_suite,
                initial_read_secret,
                initial_write_secret,
                initial_write_sequence,
            );

            var input: [inbound_application_data.len]u8 = undefined;
            const input_len = try reader.read(&input);
            try std.testing.expectEqual(inbound_application_data.len, input_len);
            try std.testing.expectEqualStrings(inbound_application_data, input[0..input_len]);

            const after_read = reader.trafficState();
            try std.testing.expectEqualSlices(u8, &updated_read_secret, &after_read.read_secret);
            try std.testing.expectEqualSlices(u8, &updated_read_keys.key, &after_read.read_key);
            try std.testing.expectEqualSlices(u8, &updated_read_keys.iv, &after_read.read_iv);
            try std.testing.expectEqual(@as(u64, 1), after_read.read_seq);
            try std.testing.expectEqual(@as(usize, 0), after_read.post_handshake_len);

            var record_buf: [4096]u8 = undefined;
            if (request == .update_requested) {
                var response_sequence = initial_write_sequence;
                const response = try readTestTLS13Record(
                    &peer,
                    case.cipher_suite,
                    initial_write_keys.key,
                    initial_write_keys.iv,
                    &response_sequence,
                    &record_buf,
                );
                try std.testing.expectEqual(
                    @intFromEnum(ContentType.handshake),
                    response.content_type,
                );
                const expected_response = [_]u8{
                    @intFromEnum(tls.HandshakeType.key_update),
                    0,
                    0,
                    1,
                    @intFromEnum(tls.KeyUpdateRequest.update_not_requested),
                };
                try std.testing.expectEqualSlices(u8, &expected_response, response.content);

                const updated_write_secret = testUpdatedTrafficSecret(
                    case.cipher_suite,
                    &initial_write_secret,
                );
                const updated_write_keys = testTrafficKeys(case.cipher_suite, &updated_write_secret);
                try std.testing.expectEqualSlices(u8, &updated_write_secret, &after_read.write_secret);
                try std.testing.expectEqualSlices(u8, &updated_write_keys.key, &after_read.write_key);
                try std.testing.expectEqualSlices(u8, &updated_write_keys.iv, &after_read.write_iv);
                try std.testing.expectEqual(@as(u64, 0), after_read.write_seq);

                try std.testing.expectEqual(
                    outbound_application_data.len,
                    try reader.write(outbound_application_data),
                );
                var outbound_sequence: u64 = 0;
                const outbound = try readTestTLS13Record(
                    &peer,
                    case.cipher_suite,
                    updated_write_keys.key,
                    updated_write_keys.iv,
                    &outbound_sequence,
                    &record_buf,
                );
                try std.testing.expectEqual(
                    @intFromEnum(ContentType.application_data),
                    outbound.content_type,
                );
                try std.testing.expectEqualStrings(outbound_application_data, outbound.content);
                try std.testing.expectEqual(@as(u64, 1), reader.trafficState().write_seq);
            } else {
                try std.testing.expectEqualSlices(u8, &initial_write_secret, &after_read.write_secret);
                try std.testing.expectEqualSlices(u8, &initial_write_keys.key, &after_read.write_key);
                try std.testing.expectEqualSlices(u8, &initial_write_keys.iv, &after_read.write_iv);
                try std.testing.expectEqual(initial_write_sequence, after_read.write_seq);

                try std.testing.expectEqual(
                    outbound_application_data.len,
                    try reader.write(outbound_application_data),
                );
                var outbound_sequence = initial_write_sequence;
                const outbound = try readTestTLS13Record(
                    &peer,
                    case.cipher_suite,
                    initial_write_keys.key,
                    initial_write_keys.iv,
                    &outbound_sequence,
                    &record_buf,
                );
                try std.testing.expectEqual(
                    @intFromEnum(ContentType.application_data),
                    outbound.content_type,
                );
                try std.testing.expectEqualStrings(outbound_application_data, outbound.content);
                try std.testing.expectEqual(initial_write_sequence + 1, reader.trafficState().write_seq);
            }
        }
    }
}

test "TLS application reads skip empty records before returning data" {
    const paths = [_]TestWritePath{ .connection, .session };
    const versions = [_]tls.ProtocolVersion{ .tls_1_2, .tls_1_3 };
    const message = "after empty";

    for (paths) |path| {
        for (versions) |version| {
            const cipher_suite = testReadCipherSuite(path, version);
            var wire = std.ArrayList(u8).empty;
            defer wire.deinit(std.testing.allocator);
            try appendTestProtectedRecord(
                &wire,
                version,
                cipher_suite,
                0,
                "",
                @intFromEnum(ContentType.application_data),
                if (version == .tls_1_3) 4 else 0,
                true,
            );
            try appendTestProtectedRecord(
                &wire,
                version,
                cipher_suite,
                1,
                message,
                @intFromEnum(ContentType.application_data),
                if (version == .tls_1_3) 9 else 0,
                true,
            );

            const sockets = try testSocketPair();
            var sender = sockets[0];
            defer sender.close();
            var receiver = sockets[1];
            defer receiver.close();
            try sender.sendAll(wire.items);

            var reader = TestApplicationReader.init(path, &receiver, version, cipher_suite);
            var output: [message.len]u8 = undefined;
            const first_len = try reader.read(output[0..4]);
            try std.testing.expectEqual(@as(usize, 4), first_len);
            try std.testing.expectEqualStrings(message[0..4], output[0..first_len]);
            try std.testing.expectEqual(@as(u64, 2), reader.sequence());

            const second_len = try reader.read(output[first_len..]);
            try std.testing.expectEqual(message.len - first_len, second_len);
            try std.testing.expectEqualStrings(message[first_len..], output[first_len..][0..second_len]);
            try std.testing.expectEqual(@as(u64, 2), reader.sequence());
        }
    }
}

test "TLS application reads bound consecutive empty record processing" {
    const path: TestWritePath = .connection;
    const cipher_suite = testReadCipherSuite(path, .tls_1_3);
    var wire = std.ArrayList(u8).empty;
    defer wire.deinit(std.testing.allocator);
    for (0..max_skipped_records_per_read + 1) |sequence| {
        try appendTestProtectedRecord(
            &wire,
            .tls_1_3,
            cipher_suite,
            sequence,
            "",
            @intFromEnum(ContentType.application_data),
            0,
            true,
        );
    }

    const sockets = try testSocketPair();
    var sender = sockets[0];
    defer sender.close();
    var receiver = sockets[1];
    defer receiver.close();
    try sender.sendAll(wire.items);

    var reader = TestApplicationReader.init(path, &receiver, .tls_1_3, cipher_suite);
    var output: [1]u8 = undefined;
    try std.testing.expectError(error.TlsUnexpectedMessage, reader.read(&output));
    try std.testing.expectEqual(@as(u64, max_skipped_records_per_read + 1), reader.sequence());
}

test "TLS 1.2 ChaCha records use implicit nonces and round trip bidirectionally" {
    const message = "forced TLS 1.2 ChaCha20-Poly1305 record";
    const initial_seq: u64 = 0x0102030405060708;
    var scripted_sender = ScriptedSender{
        .allocator = std.testing.allocator,
        .max_chunk = 9,
    };
    defer scripted_sender.deinit();
    var scripted_writer = ScriptedRecordWriter{
        .sender = &scripted_sender,
        .version = .tls_1_2,
        .cipher_suite = .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .sequence = initial_seq,
    };
    try std.testing.expectEqual(message.len, try scripted_writer.write(message));
    try std.testing.expectEqual(initial_seq + 1, scripted_writer.sequence);
    try std.testing.expectEqual(
        record_header_len + message.len + crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length,
        scripted_sender.bytes.items.len,
    );
    try std.testing.expectEqual(
        message.len + crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length,
        mem.readInt(u16, scripted_sender.bytes.items[3..5], .big),
    );

    var aad: [record_header_len + 8]u8 = undefined;
    mem.writeInt(u64, aad[0..8], initial_seq, .big);
    @memcpy(aad[8..11], scripted_sender.bytes.items[0..3]);
    mem.writeInt(u16, aad[11..13], message.len, .big);
    const expected_nonce = nonceTLS13(&test_write_iv, initial_seq);
    var expected_ciphertext: [message.len]u8 = undefined;
    var expected_tag: [crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length]u8 = undefined;
    crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        &expected_ciphertext,
        &expected_tag,
        message,
        &aad,
        expected_nonce,
        test_write_key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_ciphertext,
        scripted_sender.bytes.items[record_header_len..][0..message.len],
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_tag,
        scripted_sender.bytes.items[record_header_len + message.len ..],
    );

    const round_trip = try std.testing.allocator.dupe(u8, scripted_sender.bytes.items);
    defer std.testing.allocator.free(round_trip);
    const decrypted = try decryptTLS12ForSuite(
        round_trip[record_header_len..],
        round_trip[0..record_header_len],
        initial_seq,
        &test_write_iv,
        &test_write_key,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    );
    try std.testing.expectEqualStrings(message, decrypted);

    const tampered = try std.testing.allocator.dupe(u8, scripted_sender.bytes.items);
    defer std.testing.allocator.free(tampered);
    tampered[record_header_len] ^= 0x80;
    try std.testing.expectError(
        error.TlsDecryptError,
        decryptTLS12ForSuite(
            tampered[record_header_len..],
            tampered[0..record_header_len],
            initial_seq,
            &test_write_iv,
            &test_write_key,
            .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ),
    );

    const production_tampered = try std.testing.allocator.dupe(u8, scripted_sender.bytes.items);
    defer std.testing.allocator.free(production_tampered);
    production_tampered[record_header_len + 1] ^= 0x40;
    const sockets = try testSocketPair();
    var sender = sockets[0];
    defer sender.close();
    var receiver = sockets[1];
    defer receiver.close();
    try sender.sendAll(production_tampered);
    var conn = Connection{
        .allocator = std.testing.allocator,
        .socket = &receiver,
        .tls_version = .tls_1_2,
        .connected = true,
        .app_read_key = test_write_key,
        .app_read_iv = test_write_iv,
        .cipher_suite = .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .read_seq = initial_seq,
    };
    var read_buf: [128]u8 = undefined;
    try std.testing.expectError(error.TlsDecryptError, conn.read(&read_buf));
    try std.testing.expectEqual(initial_seq, conn.read_seq);

    const plaintext = try std.testing.allocator.alloc(u8, max_plaintext_len + 321);
    defer std.testing.allocator.free(plaintext);
    fillTestPlaintext(plaintext);
    try expectApplicationRoundTrip(
        .session,
        .connection,
        .tls_1_2,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        plaintext,
        4093,
    );
    try expectApplicationRoundTrip(
        .connection,
        .session,
        .tls_1_2,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        plaintext,
        4093,
    );
}

test "TLS 1.2 ChaCha handshake record helpers round trip" {
    const suites = [_]tls.CipherSuite{
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    const message = "\x14\x00\x00\x0c0123456789ab";

    for (suites) |cipher_suite| {
        const sockets = try testSocketPair();
        var sender = sockets[0];
        defer sender.close();
        var receiver = sockets[1];
        defer receiver.close();

        var write_seq: u64 = 7;
        try sendTLS12EncryptedHandshake(
            &sender,
            message,
            &test_write_key,
            &test_write_iv,
            &write_seq,
            cipher_suite,
        );
        var read_seq: u64 = 7;
        var record_buf: [4096]u8 = undefined;
        const plaintext = try readTLS12EncryptedRecord(
            &receiver,
            &record_buf,
            &test_write_key,
            &test_write_iv,
            &read_seq,
            cipher_suite,
        );
        try std.testing.expectEqualStrings(message, plaintext);
        try std.testing.expectEqual(@as(u64, 8), write_seq);
        try std.testing.expectEqual(@as(u64, 8), read_seq);
    }
}
