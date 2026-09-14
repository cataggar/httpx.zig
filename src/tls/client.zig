const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const std = @import("std");
const tls = std.crypto.tls;
const Client = @This();

const mem = std.mem;
const assert = std.debug.assert;
const provider_api = @import("crypto/provider.zig");
const cipher_types = @import("crypto/tls_state.zig");
const client_hello_encoding = @import("crypto/client_hello.zig");
const peer_trust = @import("trust.zig");
const cert_crypto = @import("cert_crypto.zig");

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const max_ciphertext_len = tls.max_ciphertext_len;
const hmacExpandLabel = cipher_types.hmacExpandLabel;
const hkdfExpandLabel = cipher_types.hkdfExpandLabel;
const int = tls.int;
const array = tls.array;

/// The encrypted stream from the server to the client. Bytes are pulled from
/// here via `reader`.
///
/// The buffer is asserted to have capacity at least `min_buffer_len`.
input: *Reader,
/// Decrypted stream from the server to the client.
reader: Reader,

/// The encrypted stream from the client to the server. Bytes are pushed here
/// via `writer`.
///
/// The buffer is asserted to have capacity at least `min_buffer_len`.
output: *Writer,
/// The plaintext stream from the client to the server.
writer: Writer,

/// Populated when `error.TlsAlert` is returned.
alert: ?tls.Alert = null,
read_err: ?ReadError = null,
tls_version: tls.ProtocolVersion,
negotiated_cipher_suite: tls.CipherSuite,
read_seq: u64,
write_seq: u64,
/// When this is true, the stream may still not be at the end because there
/// may be data in the input buffer.
received_close_notify: bool,
allow_truncation_attacks: bool,
application_cipher: cipher_types.ApplicationCipher,
crypto_provider: provider_api.CryptoProvider,
write_err: ?RecordError = null,

/// The ALPN protocol negotiated with the server, if any.
negotiated_alpn: ?[256]u8 = null,
negotiated_alpn_len: usize = 0,

/// If non-null, ssl secrets are logged to a stream. Creating such a log file
/// allows other programs with access to that file to decrypt all traffic over
/// this connection.
ssl_key_log: ?*SslKeyLog,

pub const ReadError = error{
    /// The alert description will be stored in `alert`.
    TlsAlert,
    TlsBadLength,
    TlsBadRecordMac,
    TlsConnectionTruncated,
    TlsDecodeError,
    TlsRecordOverflow,
    TlsUnexpectedMessage,
    TlsIllegalParameter,
    TlsSequenceOverflow,
} || provider_api.ProviderError || Writer.Error;

const RecordError = provider_api.ProviderError || error{TlsSequenceOverflow};

fn failWrite(c: *Client, err: RecordError) Writer.Error {
    c.write_err = err;
    return error.WriteFailed;
}

pub const SslKeyLog = struct {
    client_key_seq: u64,
    server_key_seq: u64,
    client_random: [32]u8,
    writer: *Writer,

    fn clientCounter(key_log: *@This()) u64 {
        defer key_log.client_key_seq += 1;
        return key_log.client_key_seq;
    }

    fn serverCounter(key_log: *@This()) u64 {
        defer key_log.server_key_seq += 1;
        return key_log.server_key_seq;
    }
};

/// The `Reader` supplied to `init` requires a buffer capacity
/// at least this amount.
pub const min_buffer_len = tls.max_ciphertext_record_len;

pub const Options = struct {
    crypto_provider: provider_api.CryptoProvider,
    /// Borrowed policy adapter with identical provider identity; immutable during use.
    certificate_crypto: ?*cert_crypto.CryptoCertificateVerifier = null,
    allocator: std.mem.Allocator,
    /// How to perform host verification of server certificates.
    host: union(enum) {
        /// No host verification is performed, which prevents a trusted connection from
        /// being established.
        no_verification,
        /// Verify that the server certificate was issued for a given host.
        explicit: []const u8,
    },
    /// Null is reserved for explicitly insecure configurations.
    trust_provider: ?peer_trust.TrustProvider,
    trust_limits: peer_trust.TrustLimits = .{},
    write_buffer: []u8,
    read_buffer: []u8,
    /// Cryptographically secure random bytes. The pointer is not captured; data is only
    /// read during `init`.
    entropy: *const [entropy_len]u8,
    /// Current time according to the wall clock / calendar.
    realtime_now: std.Io.Timestamp,
    /// When supplied, sample validity time when the certificate is verified.
    clock_io: ?std.Io = null,

    /// If non-null, ssl secrets are logged to this stream. Creating such a log file allows
    /// other programs with access to that file to decrypt all traffic over this connection.
    ///
    /// Only the `writer` field is observed during the handshake (`init`).
    /// After that, the other fields are populated.
    ssl_key_log: ?*SslKeyLog = null,
    /// By default, reaching the end-of-stream when reading from the server will
    /// cause `error.TlsConnectionTruncated` to be returned, unless a close_notify
    /// message has been received. By setting this flag to `true`, instead, the
    /// end-of-stream will be forwarded to the application layer above TLS.
    ///
    /// This makes the application vulnerable to truncation attacks unless the
    /// application layer itself verifies that the amount of data received equals
    /// the amount of data expected, such as HTTP with the Content-Length header.
    allow_truncation_attacks: bool = false,
    /// Populated when `error.TlsAlert` is returned from `init`.
    alert: ?*tls.Alert = null,

    /// ALPN protocols to advertise. If non-empty, an ALPN extension is added
    /// to the ClientHello. Each entry is a protocol identifier (e.g., "h2", "http/1.1").
    alpn_protocols: []const []const u8 = &.{},

    pub const entropy_len = 240;
};

pub const InitError = error{
    TlsUnsupportedCipherSuite,
    InsufficientEntropy,
    DiskQuota,
    LockViolation,
    NotOpenForWriting,
    /// The alert description will be stored in `alert`.
    TlsAlert,
    TlsUnexpectedMessage,
    TlsIllegalParameter,
    TlsDecryptFailure,
    TlsRecordOverflow,
    TlsBadRecordMac,
    CertificateFieldHasInvalidLength,
    CertificateHostMismatch,
    CertificatePublicKeyInvalid,
    CertificateExpired,
    CertificateFieldHasWrongDataType,
    CertificateIssuerMismatch,
    CertificateNotYetValid,
    CertificateSignatureAlgorithmMismatch,
    CertificateSignatureAlgorithmUnsupported,
    CertificateSignatureInvalid,
    CertificateSignatureInvalidLength,
    CertificateSignatureNamedCurveUnsupported,
    CertificateSignatureUnsupportedBitCount,
    TlsCertificateNotVerified,
    TlsBadSignatureScheme,
    TlsBadRsaSignatureBitCount,
    InvalidEncoding,
    IdentityElement,
    SignatureVerificationFailed,
    TlsDecryptError,
    TlsConnectionTruncated,
    TlsDecodeError,
    UnsupportedCertificateVersion,
    CertificateTimeInvalid,
    CertificateHasUnrecognizedObjectId,
    CertificateHasInvalidBitString,
    MessageTooLong,
    NegativeIntoUnsigned,
    TargetTooSmall,
    BufferTooSmall,
    InvalidSignature,
    NotSquare,
    NonCanonical,
    WeakPublicKey,
} || std.Io.Writer.Error || std.Io.Reader.ShortError || std.Io.Cancelable || provider_api.ProviderError || peer_trust.TrustError;

fn buildAlpnExtension(protocols: []const []const u8, out: []u8) InitError![]const u8 {
    if (protocols.len == 0) return out[0..0];

    var list_len: usize = 0;
    for (protocols) |protocol| {
        if (protocol.len == 0 or protocol.len > std.math.maxInt(u8)) {
            return error.TlsIllegalParameter;
        }
        list_len = std.math.add(usize, list_len, 1 + protocol.len) catch
            return error.TlsRecordOverflow;
    }
    if (list_len > std.math.maxInt(u16) or 6 + list_len > out.len) {
        return error.TlsRecordOverflow;
    }

    mem.writeInt(u16, out[0..2], @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation), .big);
    mem.writeInt(u16, out[2..4], @intCast(2 + list_len), .big);
    mem.writeInt(u16, out[4..6], @intCast(list_len), .big);
    var offset: usize = 6;
    for (protocols) |protocol| {
        out[offset] = @intCast(protocol.len);
        offset += 1;
        @memcpy(out[offset..][0..protocol.len], protocol);
        offset += protocol.len;
    }
    return out[0..offset];
}

fn parseSelectedAlpnProtocol(data: []const u8) error{ TlsDecodeError, TlsIllegalParameter }![]const u8 {
    if (data.len < 3) return error.TlsDecodeError;
    const list_len: usize = mem.readInt(u16, data[0..2], .big);
    if (list_len == 0 or list_len != data.len - 2) return error.TlsDecodeError;
    const protocol_len: usize = data[2];
    if (protocol_len == 0) return error.TlsIllegalParameter;
    if (protocol_len + 1 != list_len) return error.TlsDecodeError;
    return data[3..][0..protocol_len];
}

fn validateSelectedAlpnProtocol(selected: []const u8, offered: []const []const u8) error{TlsIllegalParameter}!void {
    for (offered) |protocol| {
        if (mem.eql(u8, selected, protocol)) return;
    }
    return error.TlsIllegalParameter;
}

fn validateCertificateCrypto(selected: provider_api.CryptoProvider, adapter: ?*cert_crypto.CryptoCertificateVerifier) error{TlsInvalidTrustConfiguration}!void {
    if (adapter) |bound| {
        if (!bound.matchesProvider(selected)) return error.TlsInvalidTrustConfiguration;
    }
}

/// Initiates a TLS handshake and establishes a TLSv1.2 or TLSv1.3 session.
///
/// `host` is only borrowed during this function call.
///
/// `input` is asserted to have buffer capacity at least `min_buffer_len`.
pub fn init(input: *Reader, output: *Writer, options: Options) InitError!Client {
    assert(input.buffer.len >= min_buffer_len);
    try validateCertificateCrypto(options.crypto_provider, options.certificate_crypto);
    if (options.certificate_crypto != null and (options.trust_provider == null or options.host == .no_verification))
        return error.TlsInvalidTrustConfiguration;
    const host = switch (options.host) {
        .no_verification => "",
        .explicit => |host| host,
    };
    const client_hello_rand = options.entropy[0..32].*;
    var key_seq: u64 = 0;
    var server_hello_rand: [32]u8 = undefined;
    const legacy_session_id = options.entropy[32..64].*;

    const capabilities = try options.crypto_provider.capabilities();
    var key_share = try KeyShare.init(options.crypto_provider, options.allocator);
    defer key_share.deinit();
    var alpn_buf: [4096]u8 = undefined;
    const alpn_extension = try buildAlpnExtension(options.alpn_protocols, &alpn_buf);

    var client_hello_buf: [4096]u8 = undefined;
    const client_hello = try client_hello_encoding.build(
        client_hello_buf[0 .. client_hello_buf.len - 4],
        capabilities,
        &key_share,
        options.entropy[0..64],
        host,
        alpn_extension,
    );

    // Wrap in handshake record
    var out_handshake_buf: [4096]u8 = undefined;
    out_handshake_buf[0] = @intFromEnum(tls.HandshakeType.client_hello);
    mem.writeInt(u24, out_handshake_buf[1..][0..3], @intCast(client_hello.len), .big);
    @memcpy(out_handshake_buf[4..][0..client_hello.len], client_hello);
    const out_handshake = out_handshake_buf[0 .. 4 + client_hello.len];

    // Wrap in TLS record
    var cleartext_header_buf: [8192]u8 = undefined;
    cleartext_header_buf[0] = @intFromEnum(tls.ContentType.handshake);
    mem.writeInt(u16, cleartext_header_buf[1..][0..2], @intFromEnum(tls.ProtocolVersion.tls_1_0), .big);
    mem.writeInt(u16, cleartext_header_buf[3..][0..2], @intCast(out_handshake.len), .big);
    @memcpy(cleartext_header_buf[5..][0..out_handshake.len], out_handshake);
    const total_record_len: usize = 5 + out_handshake.len;
    const cleartext_header: []const u8 = cleartext_header_buf[0..total_record_len];

    {
        try output.writeAll(cleartext_header);
        try output.flush();
    }

    var tls_version: tls.ProtocolVersion = undefined;
    var negotiated_cipher_suite: tls.CipherSuite = undefined;
    var write_seq: u64 = 0;
    var read_seq: u64 = 0;
    const CipherState = enum {
        /// No cipher is in use
        cleartext,
        /// Handshake cipher is in use
        handshake,
        /// Application cipher is in use
        application,
    };
    var pending_cipher_state: CipherState = .cleartext;
    var cipher_state = pending_cipher_state;
    const HandshakeState = enum {
        /// In this state we expect only a server hello message.
        hello,
        /// In this state we expect only an encrypted_extensions message.
        encrypted_extensions,
        /// In this state we expect certificate handshake messages.
        certificate,
        /// In this state we expect certificate or certificate_verify messages.
        /// certificate messages are ignored since the trust chain is already
        /// established.
        trust_chain_established,
        /// In this state, we expect only the server_hello_done handshake message.
        server_hello_done,
        /// In this state, we expect only the finished handshake message.
        finished,
    };
    var handshake_state: HandshakeState = .hello;
    var handshake_cipher: cipher_types.HandshakeCipher = undefined;
    var handshake_cipher_initialized = false;
    defer if (handshake_cipher_initialized) handshake_cipher.deinit();
    var main_cert_pub_key: CertificatePublicKey = undefined;
    var tls12_negotiated_group: ?tls.NamedGroup = null;
    var tls12_extended_master_secret = false;
    var negotiated_alpn: ?[256]u8 = null;
    var negotiated_alpn_len: usize = 0;
    var server_hello_alpn_present = false;

    const message_limit = @min(
        std.math.add(usize, options.trust_limits.max_chain_der_bytes, 65536) catch return error.TlsRecordOverflow,
        2 * 1024 * 1024,
    );
    var messages = @import("crypto/handshake_buffer.zig").Buffer.init(options.allocator, message_limit);
    defer messages.deinit();
    var cleartext_record: [tls.max_ciphertext_len]u8 = undefined;
    defer provider_api.secureWipe(&cleartext_record);
    var skipped_ccs: usize = 0;
    var empty_records: usize = 0;
    fragment: while (true) {
        // Ensure the input buffer pointer is stable in this scope.
        input.rebase(tls.max_ciphertext_record_len) catch |err| switch (err) {
            error.EndOfStream => {}, // We have assurance the remainder of stream can be buffered.
            error.ReadFailed => |e| return e,
        };
        const record_header = input.peek(tls.record_header_len) catch |err| switch (err) {
            error.EndOfStream => return error.TlsConnectionTruncated,
            error.ReadFailed => |e| return e,
        };
        const record_ct = input.takeEnumNonexhaustive(tls.ContentType, .big) catch unreachable; // already peeked
        input.toss(2); // legacy_version
        const record_len = input.takeInt(u16, .big) catch unreachable; // already peeked
        if (record_len > tls.max_ciphertext_len) return error.TlsRecordOverflow;
        const record_buffer = input.take(record_len) catch |err| switch (err) {
            error.EndOfStream => return error.TlsConnectionTruncated,
            error.ReadFailed => return error.ReadFailed,
        };
        if (record_ct == .change_cipher_spec) {
            if (!mem.eql(u8, record_buffer, "\x01") or handshake_state == .hello) return error.TlsUnexpectedMessage;
            if (tls_version == .tls_1_3) {
                if (skipped_ccs == 8) return error.TlsUnexpectedMessage;
                skipped_ccs += 1;
                continue :fragment;
            }
            if (pending_cipher_state != .application or cipher_state != .cleartext or messages.pendingLength() != 0)
                return error.TlsUnexpectedMessage;
            cipher_state = .application;
            continue :fragment;
        }
        const record_cipher_state = cipher_state;
        var record_decoder: tls.Decoder = .fromTheirSlice(record_buffer);
        const plaintext, const ct = content: switch (cipher_state) {
            .cleartext => blk: {
                if (record_buffer.len > 16384) return error.TlsRecordOverflow;
                break :blk .{ record_buffer, record_ct };
            },
            .handshake => {
                assert(tls_version == .tls_1_3);
                if (record_ct != .application_data) return error.TlsUnexpectedMessage;
                try record_decoder.ensure(record_len);
                var plaintext_length: usize = 0;
                switch (handshake_cipher) {
                    inline else => |*p| {
                        const pv = &p.version.tls_1_3;
                        const P = @TypeOf(p.*).A;
                        if (record_len < P.AEAD.tag_length) return error.TlsRecordOverflow;
                        const ciphertext = record_decoder.slice(record_len - P.AEAD.tag_length);
                        if (ciphertext.len > cleartext_record.len) return error.TlsRecordOverflow;
                        const cleartext = cleartext_record[0..ciphertext.len];
                        const auth_tag = record_decoder.array(P.AEAD.tag_length).*;
                        const nonce = nonce: {
                            const V = @Vector(P.AEAD.nonce_length, u8);
                            const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                            const operand: V = pad ++ @as([8]u8, @bitCast(big(read_seq)));
                            break :nonce @as(V, pv.server_handshake_iv) ^ operand;
                        };
                        P.AEAD.decrypt(options.crypto_provider, cleartext, ciphertext, auth_tag, record_header, nonce, pv.server_handshake_key) catch |err|
                            return if (err == error.AuthenticationFailed) error.TlsBadRecordMac else err;
                        plaintext_length = mem.trimEnd(u8, cleartext, "\x00").len;
                    },
                }
                read_seq = std.math.add(u64, read_seq, 1) catch return error.TlsRecordOverflow;
                if (plaintext_length == 0) return error.TlsDecodeError;
                plaintext_length -= 1;
                if (plaintext_length > 16384) return error.TlsRecordOverflow;
                const content_type: tls.ContentType = @enumFromInt(cleartext_record[plaintext_length]);
                break :content .{ cleartext_record[0..plaintext_length], content_type };
            },
            .application => {
                assert(tls_version == .tls_1_2);
                if (record_ct != .handshake) return error.TlsUnexpectedMessage;
                try record_decoder.ensure(record_len);
                var plaintext_length: usize = 0;
                switch (handshake_cipher) {
                    inline else => |*p| {
                        const pv = &p.version.tls_1_2;
                        const P = @TypeOf(p.*).A;
                        if (record_len < P.record_iv_length + P.mac_length) return error.TlsRecordOverflow;
                        const message_len: u16 = record_len - P.record_iv_length - P.mac_length;
                        if (message_len > 16384 or message_len > cleartext_record.len) return error.TlsRecordOverflow;
                        const cleartext = cleartext_record[0..message_len];
                        const ad = mem.toBytes(big(read_seq)) ++
                            record_header[0 .. 1 + 2] ++
                            mem.toBytes(big(message_len));
                        const record_iv = record_decoder.array(P.record_iv_length).*;
                        const masked_read_seq = read_seq &
                            comptime std.math.shl(u64, std.math.maxInt(u64), 8 * P.record_iv_length);
                        const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                            const V = @Vector(P.AEAD.nonce_length, u8);
                            const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                            const operand: V = pad ++ @as([8]u8, @bitCast(big(masked_read_seq)));
                            break :nonce @as(V, pv.app_cipher.server_write_IV ++ record_iv) ^ operand;
                        };
                        const ciphertext = record_decoder.slice(message_len);
                        const auth_tag = record_decoder.array(P.mac_length);
                        P.AEAD.decrypt(options.crypto_provider, cleartext, ciphertext, auth_tag.*, ad, nonce, pv.app_cipher.server_write_key) catch |err|
                            return if (err == error.AuthenticationFailed) error.TlsBadRecordMac else err;
                        plaintext_length = message_len;
                    },
                }
                read_seq = std.math.add(u64, read_seq, 1) catch return error.TlsRecordOverflow;
                break :content .{ cleartext_record[0..plaintext_length], record_ct };
            },
        };
        switch (ct) {
            .alert => {
                if (messages.pendingLength() != 0 or plaintext.len != 2) return error.TlsUnexpectedMessage;
                var alert_decoder = tls.Decoder.fromTheirSlice(plaintext);
                try alert_decoder.ensure(2);
                if (options.alert) |a| a.* = .{
                    .level = alert_decoder.decode(tls.Alert.Level),
                    .description = alert_decoder.decode(tls.Alert.Description),
                };
                return error.TlsAlert;
            },
            .handshake => {
                if (plaintext.len == 0) {
                    empty_records += 1;
                    if (empty_records == 32) return error.TlsUnexpectedMessage;
                    continue :fragment;
                }
                empty_records = 0;
                try messages.append(plaintext);
                while (try messages.peek()) |wrapped_handshake| {
                    var ctd = tls.Decoder.fromTheirSlice(wrapped_handshake);
                    try ctd.ensure(4);
                    const handshake_type = ctd.decode(tls.HandshakeType);
                    const handshake_len = ctd.decode(u24);
                    var hsd = try ctd.sub(handshake_len);
                    switch (handshake_type) {
                        .server_hello => {
                            if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                            if (handshake_state != .hello) return error.TlsUnexpectedMessage;
                            try hsd.ensure(2 + 32 + 1);
                            const legacy_version = hsd.decode(u16);
                            @memcpy(&server_hello_rand, hsd.array(32));
                            if (mem.eql(u8, &server_hello_rand, &tls.hello_retry_request_sequence)) {
                                // This is a HelloRetryRequest message. This client implementation
                                // does not expect to get one.
                                return error.TlsUnexpectedMessage;
                            }
                            const legacy_session_id_echo_len = hsd.decode(u8);
                            try hsd.ensure(legacy_session_id_echo_len + 2 + 1);
                            const legacy_session_id_echo = hsd.slice(legacy_session_id_echo_len);
                            const cipher_suite_tag = hsd.decode(tls.CipherSuite);
                            hsd.skip(1); // legacy_compression_method
                            var supported_version: ?u16 = null;
                            if (!hsd.eof()) {
                                try hsd.ensure(2);
                                const extensions_size = hsd.decode(u16);
                                var all_extd = try hsd.sub(extensions_size);
                                while (!all_extd.eof()) {
                                    try all_extd.ensure(2 + 2);
                                    const et = all_extd.decode(tls.ExtensionType);
                                    const ext_size = all_extd.decode(u16);
                                    var extd = try all_extd.sub(ext_size);
                                    switch (et) {
                                        client_hello_encoding.extended_master_secret => {
                                            if (tls12_extended_master_secret or ext_size != 0) return error.TlsIllegalParameter;
                                            tls12_extended_master_secret = true;
                                        },
                                        .supported_versions => {
                                            if (supported_version) |_| return error.TlsIllegalParameter;
                                            try extd.ensure(2);
                                            supported_version = extd.decode(u16);
                                        },
                                        .key_share => {
                                            if (key_share.getSharedSecret()) |_| return error.TlsIllegalParameter;
                                            try extd.ensure(4);
                                            const named_group = extd.decode(tls.NamedGroup);
                                            const key_size = extd.decode(u16);
                                            try extd.ensure(key_size);
                                            try key_share.exchange(named_group, extd.slice(key_size));
                                        },
                                        .application_layer_protocol_negotiation => {
                                            if (negotiated_alpn != null) return error.TlsIllegalParameter;
                                            try extd.ensure(ext_size);
                                            const selected = try parseSelectedAlpnProtocol(extd.slice(ext_size));
                                            try validateSelectedAlpnProtocol(selected, options.alpn_protocols);
                                            var buf: [256]u8 = undefined;
                                            @memcpy(buf[0..selected.len], selected);
                                            negotiated_alpn = buf;
                                            negotiated_alpn_len = selected.len;
                                            server_hello_alpn_present = true;
                                        },
                                        else => {},
                                    }
                                }
                            }

                            tls_version = @enumFromInt(supported_version orelse legacy_version);
                            if (!client_hello_encoding.offered(capabilities, cipher_suite_tag, tls_version))
                                return error.TlsUnsupportedCipherSuite;
                            negotiated_cipher_suite = cipher_suite_tag;
                            switch (tls_version) {
                                .tls_1_3 => {
                                    if (tls12_extended_master_secret) return error.TlsIllegalParameter;
                                    if (!mem.eql(u8, legacy_session_id_echo, &legacy_session_id)) return error.TlsIllegalParameter;
                                    if (server_hello_alpn_present) return error.TlsIllegalParameter;
                                },
                                .tls_1_2 => if (client_hello_encoding.versionOffered(capabilities, .tls_1_3) and
                                    mem.eql(u8, server_hello_rand[24..31], "DOWNGRD") and
                                    server_hello_rand[31] >> 1 == 0x00) return error.TlsIllegalParameter,
                                else => return error.TlsIllegalParameter,
                            }

                            switch (cipher_suite_tag) {
                                inline .AES_128_GCM_SHA256,
                                .AES_256_GCM_SHA384,
                                .CHACHA20_POLY1305_SHA256,
                                .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                                .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                                => |tag| {
                                    handshake_cipher = @unionInit(cipher_types.HandshakeCipher, @tagName(tag.with()), .{
                                        .transcript_hash = try .init(options.crypto_provider, options.allocator),
                                        .version = undefined,
                                    });
                                    handshake_cipher_initialized = true;
                                    const p = &@field(handshake_cipher, @tagName(tag.with()));
                                    try p.transcript_hash.update(cleartext_header[tls.record_header_len..]); // Client Hello
                                    try p.transcript_hash.update(wrapped_handshake);
                                },

                                else => return error.TlsIllegalParameter,
                            }
                            switch (tls_version) {
                                .tls_1_3 => {
                                    switch (cipher_suite_tag) {
                                        inline .AES_128_GCM_SHA256,
                                        .AES_256_GCM_SHA384,
                                        .CHACHA20_POLY1305_SHA256,
                                        => |tag| {
                                            const sk = key_share.getSharedSecret() orelse return error.TlsIllegalParameter;
                                            const p = &@field(handshake_cipher, @tagName(tag.with()));
                                            const P = @TypeOf(p.*).A;
                                            const hello_hash = try p.transcript_hash.peek();
                                            const zeroes = [1]u8{0} ** P.Hash.digest_length;
                                            var early_secret = try P.Hkdf.extract(options.crypto_provider, &[1]u8{0}, &zeroes);
                                            defer provider_api.secureWipe(&early_secret);
                                            const empty_hash = try cipher_types.emptyHash(options.crypto_provider, options.allocator, P.Hash);
                                            p.version = .{ .tls_1_3 = undefined };
                                            const pv = &p.version.tls_1_3;
                                            var hs_derived_secret = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, early_secret, "derived", &empty_hash, P.Hash.digest_length);
                                            defer provider_api.secureWipe(&hs_derived_secret);
                                            pv.handshake_secret = try P.Hkdf.extract(options.crypto_provider, &hs_derived_secret, sk);
                                            var ap_derived_secret = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, pv.handshake_secret, "derived", &empty_hash, P.Hash.digest_length);
                                            defer provider_api.secureWipe(&ap_derived_secret);
                                            pv.master_secret = try P.Hkdf.extract(options.crypto_provider, &ap_derived_secret, &zeroes);
                                            var client_secret = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, pv.handshake_secret, "c hs traffic", &hello_hash, P.Hash.digest_length);
                                            defer provider_api.secureWipe(&client_secret);
                                            var server_secret = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, pv.handshake_secret, "s hs traffic", &hello_hash, P.Hash.digest_length);
                                            defer provider_api.secureWipe(&server_secret);
                                            if (options.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                                .client_random = &client_hello_rand,
                                            }, .{
                                                .SERVER_HANDSHAKE_TRAFFIC_SECRET = &server_secret,
                                                .CLIENT_HANDSHAKE_TRAFFIC_SECRET = &client_secret,
                                            });
                                            pv.client_finished_key = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, client_secret, "finished", "", P.Hmac.key_length);
                                            pv.server_finished_key = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, server_secret, "finished", "", P.Hmac.key_length);
                                            pv.client_handshake_key = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, client_secret, "key", "", P.AEAD.key_length);
                                            pv.server_handshake_key = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, server_secret, "key", "", P.AEAD.key_length);
                                            pv.client_handshake_iv = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, client_secret, "iv", "", P.AEAD.nonce_length);
                                            pv.server_handshake_iv = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, server_secret, "iv", "", P.AEAD.nonce_length);
                                        },
                                        else => return error.TlsIllegalParameter,
                                    }
                                    pending_cipher_state = .handshake;
                                    // TLS 1.3 CCS records are optional compatibility
                                    // signals, not the trigger for activating keys.
                                    cipher_state = .handshake;
                                    handshake_state = .encrypted_extensions;
                                },
                                .tls_1_2 => switch (cipher_suite_tag) {
                                    .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                    .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                    .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                                    .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                    .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                    .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                                    => handshake_state = .certificate,
                                    else => return error.TlsIllegalParameter,
                                },
                                else => return error.TlsIllegalParameter,
                            }
                        },
                        .encrypted_extensions => {
                            if (tls_version != .tls_1_3) return error.TlsUnexpectedMessage;
                            if (cipher_state != .handshake) return error.TlsUnexpectedMessage;
                            if (handshake_state != .encrypted_extensions) return error.TlsUnexpectedMessage;
                            switch (handshake_cipher) {
                                inline else => |*p| try p.transcript_hash.update(wrapped_handshake),
                            }
                            try hsd.ensure(2);
                            const total_ext_size = hsd.decode(u16);
                            var all_extd = try hsd.sub(total_ext_size);
                            while (!all_extd.eof()) {
                                try all_extd.ensure(4);
                                const et = all_extd.decode(tls.ExtensionType);
                                const ext_size = all_extd.decode(u16);
                                var extd = try all_extd.sub(ext_size);
                                switch (et) {
                                    .server_name => {},
                                    .application_layer_protocol_negotiation => {
                                        if (negotiated_alpn != null) return error.TlsIllegalParameter;
                                        try extd.ensure(ext_size);
                                        const selected = try parseSelectedAlpnProtocol(extd.slice(ext_size));
                                        try validateSelectedAlpnProtocol(selected, options.alpn_protocols);
                                        var buf: [256]u8 = undefined;
                                        @memcpy(buf[0..selected.len], selected);
                                        negotiated_alpn = buf;
                                        negotiated_alpn_len = selected.len;
                                    },
                                    else => {},
                                }
                            }
                            handshake_state = .certificate;
                        },
                        .certificate => {
                            if (cipher_state == .application) return error.TlsUnexpectedMessage;
                            switch (handshake_state) {
                                .certificate => {},
                                else => return error.TlsUnexpectedMessage,
                            }
                            switch (handshake_cipher) {
                                inline else => |*p| try p.transcript_hash.update(wrapped_handshake),
                            }

                            switch (tls_version) {
                                .tls_1_3 => {
                                    try hsd.ensure(1 + 3);
                                    const cert_req_ctx_len = hsd.decode(u8);
                                    if (cert_req_ctx_len != 0) return error.TlsIllegalParameter;
                                },
                                .tls_1_2 => try hsd.ensure(3),
                                else => unreachable,
                            }
                            const certs_size = hsd.decode(u24);
                            const certs = try hsd.sub(certs_size);
                            if (!hsd.eof()) return error.TlsDecodeError;

                            var certs_decoder = certs;
                            var peer_certificates: [16][]const u8 = undefined;
                            var certificate_count: usize = 0;
                            while (!certs_decoder.eof()) {
                                try certs_decoder.ensure(3);
                                const cert_size = certs_decoder.decode(u24);
                                const certd = try certs_decoder.sub(cert_size);
                                if (certificate_count == peer_certificates.len or certificate_count == options.trust_limits.max_peer_certificates)
                                    return error.TlsCertificateChainTooLarge;
                                if (certd.buf.len == 0) return error.TlsMalformedCertificate;
                                if (certd.buf.len > options.trust_limits.max_certificate_der_bytes) return error.TlsCertificateTooLarge;
                                peer_certificates[certificate_count] = certd.rest();
                                certificate_count += 1;

                                if (tls_version == .tls_1_3) {
                                    try certs_decoder.ensure(2);
                                    const total_ext_size = certs_decoder.decode(u16);
                                    const all_extd = try certs_decoder.sub(total_ext_size);
                                    _ = all_extd;
                                }
                            }
                            if (certificate_count == 0) return error.TlsMalformedCertificateChain;
                            try validateCertificateCrypto(options.crypto_provider, options.certificate_crypto);
                            var signature_verifier = cert_crypto.CryptoCertificateVerifier.init(options.crypto_provider);
                            const identity: ?peer_trust.PeerIdentity = switch (options.host) {
                                .no_verification => null,
                                .explicit => peerIdentity(host),
                            };
                            const verification = peer_trust.VerifyPeerRequest{
                                .role = .server,
                                .chain_der = peer_certificates[0..certificate_count],
                                .expected_identity = identity,
                                .now_seconds = if (options.clock_io) |io| std.Io.Timestamp.now(io, .real).toSeconds() else options.realtime_now.toSeconds(),
                                .signature_verifier = if (options.certificate_crypto) |adapter| adapter.verifier() else signature_verifier.verifier(),
                                .scratch_allocator = options.allocator,
                                .limits = options.trust_limits,
                            };
                            try verification.validate();
                            if (options.trust_provider) |trust_provider| {
                                if (identity == null) return error.TlsInvalidTrustConfiguration;
                                try trust_provider.verifyPeer(verification);
                            }
                            const public_key = cert_crypto.certificatePublicKeyInfo(peer_certificates[0]) catch |err| switch (err) {
                                error.InvalidEncoding => return error.TlsMalformedCertificate,
                                error.UnsupportedAlgorithm => return error.UnsupportedAlgorithm,
                            };
                            try main_cert_pub_key.init(public_key);
                            handshake_state = .trust_chain_established;
                        },
                        .server_key_exchange => {
                            if (tls_version != .tls_1_2) return error.TlsUnexpectedMessage;
                            if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                            switch (handshake_state) {
                                .trust_chain_established => {},
                                .certificate => return error.TlsCertificateNotVerified,
                                else => return error.TlsUnexpectedMessage,
                            }

                            switch (handshake_cipher) {
                                inline else => |*p| try p.transcript_hash.update(wrapped_handshake),
                            }
                            try hsd.ensure(1 + 2 + 1);
                            const curve_type = hsd.decode(u8);
                            if (curve_type != 0x03) return error.TlsIllegalParameter; // named_curve
                            const named_group = hsd.decode(tls.NamedGroup);
                            tls12_negotiated_group = named_group;
                            const key_size = hsd.decode(u8);
                            try hsd.ensure(key_size);
                            const server_pub_key = hsd.slice(key_size);
                            try main_cert_pub_key.verifySignature(options.crypto_provider, tls_version, negotiated_cipher_suite, &hsd, &.{ &client_hello_rand, &server_hello_rand, hsd.buf[0..hsd.idx] });
                            try key_share.exchange(named_group, server_pub_key);
                            handshake_state = .server_hello_done;
                        },
                        .server_hello_done => {
                            if (tls_version != .tls_1_2) return error.TlsUnexpectedMessage;
                            if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                            if (handshake_state != .server_hello_done) return error.TlsUnexpectedMessage;

                            const public_key_bytes = key_share.publicKey(tls12_negotiated_group orelse return error.TlsIllegalParameter) orelse return error.TlsIllegalParameter;

                            const client_key_exchange_prefix = .{@intFromEnum(tls.ContentType.handshake)} ++
                                int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                                int(u16, @intCast(public_key_bytes.len + 5)) ++ // record length
                                .{@intFromEnum(tls.HandshakeType.client_key_exchange)} ++
                                int(u24, @intCast(public_key_bytes.len + 1)) ++ // handshake message length
                                .{@as(u8, @intCast(public_key_bytes.len))}; // public key length
                            const client_change_cipher_spec_msg = .{@intFromEnum(tls.ContentType.change_cipher_spec)} ++
                                int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                                array(u16, tls.ChangeCipherSpecType, .{.change_cipher_spec});
                            const pre_master_secret = key_share.getSharedSecret().?;
                            switch (handshake_cipher) {
                                inline else => |*p| {
                                    const P = @TypeOf(p.*).A;
                                    try p.transcript_hash.update(wrapped_handshake);
                                    try p.transcript_hash.update(client_key_exchange_prefix[tls.record_header_len..]);
                                    try p.transcript_hash.update(public_key_bytes);
                                    var master_secret = if (tls12_extended_master_secret)
                                        try hmacExpandLabel(options.crypto_provider, P.Hmac, pre_master_secret, &.{ "extended master secret", &(try p.transcript_hash.peek()) }, 48)
                                    else
                                        try hmacExpandLabel(options.crypto_provider, P.Hmac, pre_master_secret, &.{
                                            "master secret",
                                            &client_hello_rand,
                                            &server_hello_rand,
                                        }, 48);
                                    defer provider_api.secureWipe(&master_secret);
                                    if (options.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                        .client_random = &client_hello_rand,
                                    }, .{
                                        .CLIENT_RANDOM = &master_secret,
                                    });
                                    var key_block = try hmacExpandLabel(
                                        options.crypto_provider,
                                        P.Hmac,
                                        &master_secret,
                                        &.{ "key expansion", &server_hello_rand, &client_hello_rand },
                                        @sizeOf(P.Tls_1_2),
                                    );
                                    defer provider_api.secureWipe(&key_block);
                                    const client_verify_cleartext = .{@intFromEnum(tls.HandshakeType.finished)} ++
                                        array(u24, u8, try hmacExpandLabel(
                                            options.crypto_provider,
                                            P.Hmac,
                                            &master_secret,
                                            &.{ "client finished", &(try p.transcript_hash.peek()) },
                                            P.verify_data_length,
                                        ));
                                    try p.transcript_hash.update(&client_verify_cleartext);
                                    p.version = .{ .tls_1_2 = .{
                                        .expected_server_verify_data = try hmacExpandLabel(
                                            options.crypto_provider,
                                            P.Hmac,
                                            &master_secret,
                                            &.{ "server finished", &(try p.transcript_hash.finalResult()) },
                                            P.verify_data_length,
                                        ),
                                        .app_cipher = mem.bytesToValue(P.Tls_1_2, &key_block),
                                    } };
                                    const pv = &p.version.tls_1_2;
                                    const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                                        const V = @Vector(P.AEAD.nonce_length, u8);
                                        const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                                        const operand: V = pad ++ @as([8]u8, @bitCast(big(write_seq)));
                                        break :nonce @as(V, pv.app_cipher.client_write_IV ++ pv.app_cipher.client_salt) ^ operand;
                                    };
                                    var client_verify_msg = .{@intFromEnum(tls.ContentType.handshake)} ++
                                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                                        array(u16, u8, nonce[P.fixed_iv_length..].* ++
                                            @as([client_verify_cleartext.len + P.mac_length]u8, undefined));
                                    try P.AEAD.encrypt(
                                        options.crypto_provider,
                                        client_verify_msg[client_verify_msg.len - P.mac_length -
                                            client_verify_cleartext.len ..][0..client_verify_cleartext.len],
                                        client_verify_msg[client_verify_msg.len - P.mac_length ..][0..P.mac_length],
                                        &client_verify_cleartext,
                                        mem.toBytes(big(write_seq)) ++ client_verify_msg[0 .. 1 + 2] ++ int(u16, client_verify_cleartext.len),
                                        nonce,
                                        pv.app_cipher.client_write_key,
                                    );
                                    var all_msgs_vec: [4][]const u8 = .{
                                        &client_key_exchange_prefix,
                                        public_key_bytes,
                                        &client_change_cipher_spec_msg,
                                        &client_verify_msg,
                                    };
                                    write_seq += 1;
                                    try output.writeVecAll(&all_msgs_vec);
                                    try output.flush();
                                },
                            }
                            pending_cipher_state = .application;
                            handshake_state = .finished;
                        },
                        .certificate_verify => {
                            if (tls_version != .tls_1_3) return error.TlsUnexpectedMessage;
                            if (cipher_state != .handshake) return error.TlsUnexpectedMessage;
                            switch (handshake_state) {
                                .trust_chain_established => {},
                                .certificate => return error.TlsCertificateNotVerified,
                                else => return error.TlsUnexpectedMessage,
                            }
                            switch (handshake_cipher) {
                                inline else => |*p| {
                                    try main_cert_pub_key.verifySignature(options.crypto_provider, tls_version, negotiated_cipher_suite, &hsd, &.{
                                        " " ** 64 ++ "TLS 1.3, server CertificateVerify\x00",
                                        &(try p.transcript_hash.peek()),
                                    });
                                    try p.transcript_hash.update(wrapped_handshake);
                                },
                            }
                            handshake_state = .finished;
                        },
                        .finished => {
                            if (messages.pendingLength() != wrapped_handshake.len) return error.TlsUnexpectedMessage;
                            if (cipher_state == .cleartext) return error.TlsUnexpectedMessage;
                            if (handshake_state != .finished) return error.TlsUnexpectedMessage;
                            // This message is to trick buggy proxies into behaving correctly.
                            const client_change_cipher_spec_msg = .{@intFromEnum(tls.ContentType.change_cipher_spec)} ++
                                int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                                array(u16, tls.ChangeCipherSpecType, .{.change_cipher_spec});
                            const app_cipher = app_cipher: switch (handshake_cipher) {
                                inline else => |*p, tag| switch (tls_version) {
                                    .tls_1_3 => {
                                        const pv = &p.version.tls_1_3;
                                        const P = @TypeOf(p.*).A;
                                        try hsd.ensure(P.Hmac.mac_length);
                                        const finished_digest = try p.transcript_hash.peek();
                                        try p.transcript_hash.update(wrapped_handshake);
                                        const expected_server_verify_data = try cipher_types.hmac(options.crypto_provider, P.Hmac, &finished_digest, &pv.server_finished_key);
                                        if (!try options.crypto_provider.constantTimeEqual(&expected_server_verify_data, hsd.array(P.Hmac.mac_length))) return error.TlsDecryptError;
                                        const handshake_hash = try p.transcript_hash.finalResult();
                                        const verify_data = try cipher_types.hmac(options.crypto_provider, P.Hmac, &handshake_hash, &pv.client_finished_key);
                                        const out_cleartext = .{@intFromEnum(tls.HandshakeType.finished)} ++
                                            array(u24, u8, verify_data) ++
                                            .{@intFromEnum(tls.ContentType.handshake)};

                                        const wrapped_len = out_cleartext.len + P.AEAD.tag_length;

                                        var finished_msg = .{@intFromEnum(tls.ContentType.application_data)} ++
                                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                                            array(u16, u8, @as([wrapped_len]u8, undefined));

                                        const ad = finished_msg[0..tls.record_header_len];
                                        const ciphertext = finished_msg[tls.record_header_len..][0..out_cleartext.len];
                                        const auth_tag = finished_msg[finished_msg.len - P.AEAD.tag_length ..];
                                        const nonce = pv.client_handshake_iv;
                                        try P.AEAD.encrypt(options.crypto_provider, ciphertext, auth_tag, &out_cleartext, ad, nonce, pv.client_handshake_key);

                                        var all_msgs_vec: [2][]const u8 = .{
                                            &client_change_cipher_spec_msg,
                                            &finished_msg,
                                        };
                                        try output.writeVecAll(&all_msgs_vec);
                                        try output.flush();

                                        var client_secret = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, pv.master_secret, "c ap traffic", &handshake_hash, P.Hash.digest_length);
                                        defer provider_api.secureWipe(&client_secret);
                                        var server_secret = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, pv.master_secret, "s ap traffic", &handshake_hash, P.Hash.digest_length);
                                        defer provider_api.secureWipe(&server_secret);
                                        if (options.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                            .counter = key_seq,
                                            .client_random = &client_hello_rand,
                                        }, .{
                                            .SERVER_TRAFFIC_SECRET = &server_secret,
                                            .CLIENT_TRAFFIC_SECRET = &client_secret,
                                        });
                                        key_seq += 1;
                                        break :app_cipher @unionInit(cipher_types.ApplicationCipher, @tagName(tag), .{ .tls_1_3 = .{
                                            .client_secret = client_secret,
                                            .server_secret = server_secret,
                                            .client_key = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, client_secret, "key", "", P.AEAD.key_length),
                                            .server_key = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, server_secret, "key", "", P.AEAD.key_length),
                                            .client_iv = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, client_secret, "iv", "", P.AEAD.nonce_length),
                                            .server_iv = try hkdfExpandLabel(options.crypto_provider, P.Hkdf, server_secret, "iv", "", P.AEAD.nonce_length),
                                        } });
                                    },
                                    .tls_1_2 => {
                                        const pv = &p.version.tls_1_2;
                                        const P = @TypeOf(p.*).A;
                                        try hsd.ensure(P.verify_data_length);
                                        if (!try options.crypto_provider.constantTimeEqual(&pv.expected_server_verify_data, hsd.array(P.verify_data_length))) return error.TlsDecryptError;
                                        break :app_cipher @unionInit(cipher_types.ApplicationCipher, @tagName(tag), .{ .tls_1_2 = pv.app_cipher });
                                    },
                                    else => unreachable,
                                },
                            };
                            if (options.ssl_key_log) |ssl_key_log| ssl_key_log.* = .{
                                .client_key_seq = key_seq,
                                .server_key_seq = key_seq,
                                .client_random = client_hello_rand,
                                .writer = ssl_key_log.writer,
                            };
                            return .{
                                .input = input,
                                .reader = .{
                                    .buffer = options.read_buffer,
                                    .vtable = &.{
                                        .stream = stream,
                                        .readVec = readVec,
                                    },
                                    .seek = 0,
                                    .end = 0,
                                },
                                .output = output,
                                .writer = .{
                                    .buffer = options.write_buffer,
                                    .vtable = &.{
                                        .drain = drain,
                                        .flush = flush,
                                    },
                                },
                                .tls_version = tls_version,
                                .negotiated_cipher_suite = negotiated_cipher_suite,
                                .read_seq = switch (tls_version) {
                                    .tls_1_3 => 0,
                                    .tls_1_2 => read_seq,
                                    else => unreachable,
                                },
                                .write_seq = switch (tls_version) {
                                    .tls_1_3 => 0,
                                    .tls_1_2 => write_seq,
                                    else => unreachable,
                                },
                                .received_close_notify = false,
                                .allow_truncation_attacks = options.allow_truncation_attacks,
                                .application_cipher = app_cipher,
                                .crypto_provider = options.crypto_provider,
                                .negotiated_alpn = negotiated_alpn,
                                .negotiated_alpn_len = negotiated_alpn_len,
                                .ssl_key_log = options.ssl_key_log,
                            };
                        },
                        else => return error.TlsUnexpectedMessage,
                    }
                    messages.consume(wrapped_handshake.len);
                    if (record_cipher_state != cipher_state and messages.pendingLength() != 0)
                        return error.TlsUnexpectedMessage;
                }
            },
            else => return error.TlsUnexpectedMessage,
        }
    }
}

fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
    const c: *Client = @alignCast(@fieldParentPtr("writer", w));
    const output = c.output;
    const ciphertext_buf = try output.writableSliceGreedy(min_buffer_len);
    var ciphertext_end: usize = 0;
    var total_clear: usize = 0;
    done: {
        {
            const buf = w.buffered();
            const prepared = prepareCiphertextRecord(c, ciphertext_buf[ciphertext_end..], buf, .application_data) catch |err| return failWrite(c, err);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
        for (data[0 .. data.len - 1]) |buf| {
            const prepared = prepareCiphertextRecord(c, ciphertext_buf[ciphertext_end..], buf, .application_data) catch |err| return failWrite(c, err);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
        const buf = data[data.len - 1];
        for (0..splat) |_| {
            const prepared = prepareCiphertextRecord(c, ciphertext_buf[ciphertext_end..], buf, .application_data) catch |err| return failWrite(c, err);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
    }
    output.advance(ciphertext_end);
    return w.consume(total_clear);
}

fn flush(w: *Writer) Writer.Error!void {
    const c: *Client = @alignCast(@fieldParentPtr("writer", w));
    const output = c.output;
    const ciphertext_buf = try output.writableSliceGreedy(min_buffer_len);
    const prepared = prepareCiphertextRecord(c, ciphertext_buf, w.buffered(), .application_data) catch |err| return failWrite(c, err);
    output.advance(prepared.ciphertext_end);
    w.end = 0;
}

/// Sends a `close_notify` alert, which is necessary for the server to
/// distinguish between a properly finished TLS session, or a truncation
/// attack.
pub fn end(c: *Client) Writer.Error!void {
    try flush(&c.writer);
    const output = c.output;
    const ciphertext_buf = try output.writableSliceGreedy(min_buffer_len);
    const prepared = prepareCiphertextRecord(c, ciphertext_buf, &tls.close_notify_alert, .alert) catch |err| return failWrite(c, err);
    output.advance(prepared.ciphertext_end);
}

fn prepareCiphertextRecord(
    c: *Client,
    ciphertext_buf: []u8,
    bytes: []const u8,
    inner_content_type: tls.ContentType,
) RecordError!struct {
    ciphertext_end: usize,
    cleartext_len: usize,
} {
    // Due to the trailing inner content type byte in the ciphertext, we need
    // an additional buffer for storing the cleartext into before encrypting.
    var cleartext_buf: [max_ciphertext_len]u8 = undefined;
    defer provider_api.secureWipe(&cleartext_buf);
    var ciphertext_end: usize = 0;
    var bytes_i: usize = 0;
    switch (c.application_cipher) {
        inline else => |*p| switch (c.tls_version) {
            .tls_1_3 => {
                const pv = &p.tls_1_3;
                const P = @TypeOf(p.*);
                const overhead_len = tls.record_header_len + P.AEAD.tag_length + 1;
                while (true) {
                    const encrypted_content_len: u16 = @min(
                        bytes.len - bytes_i,
                        tls.max_ciphertext_inner_record_len,
                        ciphertext_buf.len -| (overhead_len + ciphertext_end),
                    );
                    if (encrypted_content_len == 0) return .{
                        .ciphertext_end = ciphertext_end,
                        .cleartext_len = bytes_i,
                    };

                    @memcpy(cleartext_buf[0..encrypted_content_len], bytes[bytes_i..][0..encrypted_content_len]);
                    cleartext_buf[encrypted_content_len] = @intFromEnum(inner_content_type);
                    bytes_i += encrypted_content_len;
                    const ciphertext_len = encrypted_content_len + 1;
                    const cleartext = cleartext_buf[0..ciphertext_len];

                    const ad = ciphertext_buf[ciphertext_end..][0..tls.record_header_len];
                    ad.* = .{@intFromEnum(tls.ContentType.application_data)} ++
                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                        int(u16, ciphertext_len + P.AEAD.tag_length);
                    ciphertext_end += ad.len;
                    const ciphertext = ciphertext_buf[ciphertext_end..][0..ciphertext_len];
                    ciphertext_end += ciphertext_len;
                    const auth_tag = ciphertext_buf[ciphertext_end..][0..P.AEAD.tag_length];
                    ciphertext_end += auth_tag.len;
                    const nonce = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                        const operand: V = pad ++ mem.toBytes(big(c.write_seq));
                        break :nonce @as(V, pv.client_iv) ^ operand;
                    };
                    const next_seq = std.math.add(u64, c.write_seq, 1) catch return error.TlsSequenceOverflow;
                    try P.AEAD.encrypt(c.crypto_provider, ciphertext, auth_tag, cleartext, ad, nonce, pv.client_key);
                    c.write_seq = next_seq;
                }
            },
            .tls_1_2 => {
                const pv = &p.tls_1_2;
                const P = @TypeOf(p.*);
                const overhead_len = tls.record_header_len + P.record_iv_length + P.mac_length;
                while (true) {
                    const message_len: u16 = @min(
                        bytes.len - bytes_i,
                        tls.max_ciphertext_inner_record_len,
                        ciphertext_buf.len -| (overhead_len + ciphertext_end),
                    );
                    if (message_len == 0) return .{
                        .ciphertext_end = ciphertext_end,
                        .cleartext_len = bytes_i,
                    };

                    @memcpy(cleartext_buf[0..message_len], bytes[bytes_i..][0..message_len]);
                    bytes_i += message_len;
                    const cleartext = cleartext_buf[0..message_len];

                    const record_header = ciphertext_buf[ciphertext_end..][0..tls.record_header_len];
                    ciphertext_end += tls.record_header_len;
                    record_header.* = .{@intFromEnum(inner_content_type)} ++
                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                        int(u16, P.record_iv_length + message_len + P.mac_length);
                    const ad = mem.toBytes(big(c.write_seq)) ++ record_header[0 .. 1 + 2] ++ int(u16, message_len);
                    const record_iv = ciphertext_buf[ciphertext_end..][0..P.record_iv_length];
                    ciphertext_end += P.record_iv_length;
                    const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                        const operand: V = pad ++ @as([8]u8, @bitCast(big(c.write_seq)));
                        break :nonce @as(V, pv.client_write_IV ++ pv.client_salt) ^ operand;
                    };
                    record_iv.* = nonce[P.fixed_iv_length..].*;
                    const ciphertext = ciphertext_buf[ciphertext_end..][0..message_len];
                    ciphertext_end += message_len;
                    const auth_tag = ciphertext_buf[ciphertext_end..][0..P.mac_length];
                    ciphertext_end += P.mac_length;
                    const next_seq = std.math.add(u64, c.write_seq, 1) catch return error.TlsSequenceOverflow;
                    try P.AEAD.encrypt(c.crypto_provider, ciphertext, auth_tag, cleartext, ad, nonce, pv.client_write_key);
                    c.write_seq = next_seq;
                }
            },
            else => unreachable,
        },
    }
}

pub fn eof(c: Client) bool {
    return c.received_close_notify;
}

fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
    // This function writes exclusively to the buffer.
    _ = w;
    _ = limit;
    const c: *Client = @alignCast(@fieldParentPtr("reader", r));
    return readIndirect(c);
}

fn readVec(r: *Reader, data: [][]u8) Reader.Error!usize {
    // This function writes exclusively to the buffer.
    _ = data;
    const c: *Client = @alignCast(@fieldParentPtr("reader", r));
    return readIndirect(c);
}

fn readIndirect(c: *Client) Reader.Error!usize {
    const r = &c.reader;
    if (c.eof()) return error.EndOfStream;
    const input = c.input;
    // If at least one full encrypted record is not buffered, read once.
    const record_header = input.peek(tls.record_header_len) catch |err| switch (err) {
        error.EndOfStream => {
            // This is either a truncation attack, a bug in the server, or an
            // intentional omission of the close_notify message due to truncation
            // detection handled above the TLS layer.
            if (c.allow_truncation_attacks) {
                c.received_close_notify = true;
                return error.EndOfStream;
            } else {
                return failRead(c, error.TlsConnectionTruncated);
            }
        },
        error.ReadFailed => return error.ReadFailed,
    };
    const ct: tls.ContentType = @enumFromInt(record_header[0]);
    const legacy_version = mem.readInt(u16, record_header[1..][0..2], .big);
    _ = legacy_version;
    const record_len = mem.readInt(u16, record_header[3..][0..2], .big);
    if (record_len > max_ciphertext_len) return failRead(c, error.TlsRecordOverflow);
    const record_end = 5 + record_len;
    if (record_end > input.buffered().len) {
        input.fillMore() catch |err| switch (err) {
            error.EndOfStream => return failRead(c, error.TlsConnectionTruncated),
            error.ReadFailed => return error.ReadFailed,
        };
        if (record_end > input.buffered().len) return 0;
    }

    const cleartext_len, const inner_ct: tls.ContentType = cleartext: switch (c.application_cipher) {
        inline else => |*p| switch (c.tls_version) {
            .tls_1_3 => {
                const pv = &p.tls_1_3;
                const P = @TypeOf(p.*);
                if (ct != .application_data or record_len < P.AEAD.tag_length + 1)
                    return failRead(c, error.TlsBadLength);
                const ad = input.take(tls.record_header_len) catch unreachable; // already peeked
                const ciphertext_len = record_len - P.AEAD.tag_length;
                const ciphertext = input.take(ciphertext_len) catch unreachable; // already peeked
                const auth_tag = (input.takeArray(P.AEAD.tag_length) catch unreachable).*; // already peeked
                const nonce = nonce: {
                    const V = @Vector(P.AEAD.nonce_length, u8);
                    const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                    const operand: V = pad ++ mem.toBytes(big(c.read_seq));
                    break :nonce @as(V, pv.server_iv) ^ operand;
                };
                rebase(r, ciphertext.len);
                const cleartext = r.buffer[r.end..][0..ciphertext.len];
                P.AEAD.decrypt(c.crypto_provider, cleartext, ciphertext, auth_tag, ad, nonce, pv.server_key) catch |err|
                    return failRead(c, if (err == error.AuthenticationFailed) error.TlsBadRecordMac else err);
                const msg = mem.trimEnd(u8, cleartext, "\x00");
                if (msg.len == 0) return failRead(c, error.TlsDecodeError);
                break :cleartext .{ msg.len - 1, @enumFromInt(msg[msg.len - 1]) };
            },
            .tls_1_2 => {
                const pv = &p.tls_1_2;
                const P = @TypeOf(p.*);
                if (record_len < P.record_iv_length + P.mac_length)
                    return failRead(c, error.TlsBadLength);
                const message_len: u16 = record_len - P.record_iv_length - P.mac_length;
                const ad_header = input.take(tls.record_header_len) catch unreachable; // already peeked
                const ad = mem.toBytes(big(c.read_seq)) ++
                    ad_header[0 .. 1 + 2] ++
                    mem.toBytes(big(message_len));
                const record_iv = (input.takeArray(P.record_iv_length) catch unreachable).*; // already peeked
                const masked_read_seq = c.read_seq &
                    comptime std.math.shl(u64, std.math.maxInt(u64), 8 * P.record_iv_length);
                const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                    const V = @Vector(P.AEAD.nonce_length, u8);
                    const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                    const operand: V = pad ++ @as([8]u8, @bitCast(big(masked_read_seq)));
                    break :nonce @as(V, pv.server_write_IV ++ record_iv) ^ operand;
                };
                const ciphertext = input.take(message_len) catch unreachable; // already peeked
                const auth_tag = (input.takeArray(P.mac_length) catch unreachable).*; // already peeked
                rebase(r, ciphertext.len);
                const cleartext = r.buffer[r.end..][0..ciphertext.len];
                P.AEAD.decrypt(c.crypto_provider, cleartext, ciphertext, auth_tag, ad, nonce, pv.server_write_key) catch |err|
                    return failRead(c, if (err == error.AuthenticationFailed) error.TlsBadRecordMac else err);
                break :cleartext .{ cleartext.len, ct };
            },
            else => unreachable,
        },
    };
    const cleartext = r.buffer[r.end..][0..cleartext_len];
    c.read_seq = std.math.add(u64, c.read_seq, 1) catch return failRead(c, error.TlsSequenceOverflow);
    switch (inner_ct) {
        .alert => {
            if (cleartext.len != 2) return failRead(c, error.TlsDecodeError);
            const alert: tls.Alert = .{
                .level = @enumFromInt(cleartext[0]),
                .description = @enumFromInt(cleartext[1]),
            };
            switch (alert.description) {
                .close_notify => {
                    c.received_close_notify = true;
                    return 0;
                },
                .user_canceled => {
                    // Peer is closing the connection due to user action.
                    // Treat as a graceful close per RFC 8446 Section 6.1.
                    c.received_close_notify = true;
                    return 0;
                },
                else => {
                    c.alert = alert;
                    return failRead(c, error.TlsAlert);
                },
            }
        },
        .handshake => {
            if (c.tls_version != .tls_1_3) return failRead(c, error.TlsUnexpectedMessage);
            var ct_i: usize = 0;
            while (true) {
                if (cleartext.len - ct_i < 4) return failRead(c, error.TlsBadLength);
                const handshake_type: tls.HandshakeType = @enumFromInt(cleartext[ct_i]);
                ct_i += 1;
                const handshake_len = mem.readInt(u24, cleartext[ct_i..][0..3], .big);
                ct_i += 3;
                const next_handshake_i = ct_i + handshake_len;
                if (next_handshake_i > cleartext.len) return failRead(c, error.TlsBadLength);
                const handshake = cleartext[ct_i..next_handshake_i];
                switch (handshake_type) {
                    .new_session_ticket => {
                        // This client implementation ignores new session tickets.
                    },
                    .key_update => {
                        if (handshake.len != 1 or handshake[0] > 1) return failRead(c, error.TlsIllegalParameter);
                        switch (c.application_cipher) {
                            inline else => |*p| {
                                const pv = &p.tls_1_3;
                                const P = @TypeOf(p.*);
                                const server_secret = hkdfExpandLabel(c.crypto_provider, P.Hkdf, pv.server_secret, "traffic upd", "", P.Hash.digest_length) catch |err| return failRead(c, err);
                                if (c.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                    .counter = key_log.serverCounter(),
                                    .client_random = &key_log.client_random,
                                }, .{
                                    .SERVER_TRAFFIC_SECRET = &server_secret,
                                });
                                pv.server_secret = server_secret;
                                pv.server_key = hkdfExpandLabel(c.crypto_provider, P.Hkdf, server_secret, "key", "", P.AEAD.key_length) catch |err| return failRead(c, err);
                                pv.server_iv = hkdfExpandLabel(c.crypto_provider, P.Hkdf, server_secret, "iv", "", P.AEAD.nonce_length) catch |err| return failRead(c, err);
                            },
                        }
                        c.read_seq = 0;

                        switch (@as(tls.KeyUpdateRequest, @enumFromInt(handshake[0]))) {
                            .update_requested => {
                                c.writer.flush() catch |err| return failRead(c, err);
                                const response = [_]u8{ @intFromEnum(tls.HandshakeType.key_update), 0, 0, 1, 0 };
                                const buffer = c.output.writableSliceGreedy(min_buffer_len) catch |err| return failRead(c, err);
                                const prepared = prepareCiphertextRecord(c, buffer, &response, .handshake) catch |err| return failRead(c, err);
                                c.output.advance(prepared.ciphertext_end);
                                c.output.flush() catch |err| return failRead(c, err);
                                switch (c.application_cipher) {
                                    inline else => |*p| {
                                        const pv = &p.tls_1_3;
                                        const P = @TypeOf(p.*);
                                        const client_secret = hkdfExpandLabel(c.crypto_provider, P.Hkdf, pv.client_secret, "traffic upd", "", P.Hash.digest_length) catch |err| return failRead(c, err);
                                        if (c.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                            .counter = key_log.clientCounter(),
                                            .client_random = &key_log.client_random,
                                        }, .{
                                            .CLIENT_TRAFFIC_SECRET = &client_secret,
                                        });
                                        pv.client_secret = client_secret;
                                        pv.client_key = hkdfExpandLabel(c.crypto_provider, P.Hkdf, client_secret, "key", "", P.AEAD.key_length) catch |err| return failRead(c, err);
                                        pv.client_iv = hkdfExpandLabel(c.crypto_provider, P.Hkdf, client_secret, "iv", "", P.AEAD.nonce_length) catch |err| return failRead(c, err);
                                    },
                                }
                                c.write_seq = 0;
                            },
                            .update_not_requested => {},
                            _ => return failRead(c, error.TlsIllegalParameter),
                        }
                    },
                    else => return failRead(c, error.TlsUnexpectedMessage),
                }
                ct_i = next_handshake_i;
                if (ct_i >= cleartext.len) break;
            }
            return 0;
        },
        .application_data => {
            r.end += cleartext.len;
            return 0;
        },
        else => return failRead(c, error.TlsUnexpectedMessage),
    }
}

fn rebase(r: *Reader, capacity: usize) void {
    if (r.buffer.len - r.end >= capacity) return;
    const data = r.buffer[r.seek..r.end];
    @memmove(r.buffer[0..data.len], data);
    r.seek = 0;
    r.end = data.len;
    assert(r.buffer.len - r.end >= capacity);
}

fn failRead(c: *Client, err: ReadError) error{ReadFailed} {
    c.read_err = err;
    return error.ReadFailed;
}

fn logSecrets(w: *Writer, context: anytype, secrets: anytype) void {
    inline for (@typeInfo(@TypeOf(secrets)).@"struct".fields) |field| w.print("{s}" ++
        (if (@hasField(@TypeOf(context), "counter")) "_{d}" else "") ++ " {x} {x}\n", .{field.name} ++
        (if (@hasField(@TypeOf(context), "counter")) .{context.counter} else .{}) ++ .{
        context.client_random,
        @field(secrets, field.name),
    }) catch {};
}

fn big(x: anytype) @TypeOf(x) {
    return switch (native_endian) {
        .big => x,
        .little => @byteSwap(x),
    };
}

const KeyShare = @import("crypto/key_share.zig").KeyShare;

const CertificatePublicKey = struct {
    algo: provider_api.SignatureKeyAlgorithm,
    encoding: provider_api.PublicKeyEncoding,
    buf: [600]u8,
    len: u16,
    pss_parameters: ?cert_crypto.PssParameters = null,

    fn init(
        cert_pub_key: *CertificatePublicKey,
        info: cert_crypto.PublicKeyInfo,
    ) error{CertificatePublicKeyInvalid}!void {
        const key = info.key;
        const pub_key = key.bytes;
        if (pub_key.len > cert_pub_key.buf.len) return error.CertificatePublicKeyInvalid;
        cert_pub_key.algo = key.algorithm;
        cert_pub_key.encoding = key.encoding;
        @memcpy(cert_pub_key.buf[0..pub_key.len], pub_key);
        cert_pub_key.len = @intCast(pub_key.len);
        cert_pub_key.pss_parameters = info.pss_parameters;
    }

    const VerifyError = error{ TlsDecodeError, TlsBadSignatureScheme } || provider_api.ProviderError;

    fn verifySignature(
        cert_pub_key: *const CertificatePublicKey,
        provider: provider_api.CryptoProvider,
        version: tls.ProtocolVersion,
        cipher_suite: tls.CipherSuite,
        sigd: *tls.Decoder,
        msg: []const []const u8,
    ) VerifyError!void {
        const pub_key = cert_pub_key.buf[0..cert_pub_key.len];

        try sigd.ensure(2 + 2);
        const scheme = std.enums.fromInt(provider_api.SignatureScheme, sigd.decode(u16)) orelse return error.TlsBadSignatureScheme;
        const sig_len = sigd.decode(u16);
        try sigd.ensure(sig_len);
        const encoded_sig = sigd.slice(sig_len);
        if (!sigd.eof()) return error.TlsDecodeError;
        const capabilities = try provider.capabilities();
        if (!mem.containsAtLeast(provider_api.SignatureScheme, &client_hello_encoding.signature_schemes, 1, &.{scheme}) or
            !capabilities.supportsVerify(scheme)) return error.TlsBadSignatureScheme;
        if (version == .tls_1_3) switch (scheme) {
            .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 => return error.TlsBadSignatureScheme,
            else => {},
        };

        const algorithm = scheme.keyAlgorithm();
        if (cert_pub_key.algo != algorithm) {
            const ecdsa_key = cert_pub_key.algo == .ecdsa_p256 or cert_pub_key.algo == .ecdsa_p384;
            const ecdsa_scheme = algorithm == .ecdsa_p256 or algorithm == .ecdsa_p384;
            if (version == .tls_1_2 and ecdsa_key and ecdsa_scheme) return error.UnsupportedAlgorithm;
            return error.TlsBadSignatureScheme;
        }
        if (version == .tls_1_2) switch (algorithm) {
            .ecdsa_p256 => if (!capabilities.supportsKeyAgreement(.secp256r1)) return error.TlsBadSignatureScheme,
            .ecdsa_p384 => if (!capabilities.supportsKeyAgreement(.secp384r1)) return error.TlsBadSignatureScheme,
            else => {},
        };
        if (cert_pub_key.pss_parameters) |parameters| {
            const hash = scheme.hashAlgorithm() orelse return error.TlsBadSignatureScheme;
            if (algorithm != .rsa_pss or parameters.hash != hash or parameters.mgf_hash != hash or
                parameters.salt_length > hash.digestLength() or parameters.trailer != 1)
                return error.TlsBadSignatureScheme;
        }
        if (version == .tls_1_2) for (client_hello_encoding.suites) |suite| {
            if (suite.tag != cipher_suite) continue;
            const rsa = suite.rsa orelse return error.TlsBadSignatureScheme;
            if ((rsa and algorithm != .rsa and algorithm != .rsa_pss) or
                (!rsa and algorithm != .ecdsa_p256 and algorithm != .ecdsa_p384 and algorithm != .ed25519))
                return error.TlsBadSignatureScheme;
        };
        try provider.verify(scheme, .{
            .algorithm = algorithm,
            .encoding = cert_pub_key.encoding,
            .bytes = pub_key,
        }, msg, encoded_sig);
    }
};

test "TLS client enforces PSS leaf restrictions before selected signature dispatch" {
    const Counter = struct {
        fn verify(_: *anyopaque, _: provider_api.SignatureScheme, _: provider_api.PublicKey, _: []const []const u8, _: []const u8) provider_api.ProviderError!void {
            return error.SignatureInvalid;
        }
    };
    var standard = @import("crypto/standard.zig").StandardProvider.init(std.testing.io, std.testing.allocator);
    var table = standard.provider().vtable.*;
    table.verify = Counter.verify;
    const provider = provider_api.CryptoProvider.init(&standard, &table);
    var key: CertificatePublicKey = undefined;
    try key.init(.{
        .key = .{ .algorithm = .rsa_pss, .encoding = .rsa_pkcs1_der, .bytes = "\x30\x06\x02\x01\x03\x02\x01\x03" },
        .pss_parameters = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 32 },
    });
    var encoded: [260]u8 = @splat(0);
    mem.writeInt(u16, encoded[0..2], @intFromEnum(provider_api.SignatureScheme.rsa_pss_pss_sha384), .big);
    mem.writeInt(u16, encoded[2..4], 256, .big);
    var decoder: tls.Decoder = .{ .buf = &encoded, .their_end = encoded.len };
    try std.testing.expectError(error.TlsBadSignatureScheme, key.verifySignature(provider, .tls_1_3, .AES_128_GCM_SHA256, &decoder, &.{"message"}));
    mem.writeInt(u16, encoded[0..2], @intFromEnum(provider_api.SignatureScheme.rsa_pss_pss_sha256), .big);
    decoder = .{ .buf = &encoded, .their_end = encoded.len };
    try std.testing.expectError(error.SignatureInvalid, key.verifySignature(provider, .tls_1_3, .AES_128_GCM_SHA256, &decoder, &.{"message"}));
    key.pss_parameters.?.salt_length = 33;
    decoder = .{ .buf = &encoded, .their_end = encoded.len };
    try std.testing.expectError(error.TlsBadSignatureScheme, key.verifySignature(provider, .tls_1_2, .ECDHE_RSA_WITH_AES_128_GCM_SHA256, &decoder, &.{"message"}));
}

fn peerIdentity(host: []const u8) peer_trust.PeerIdentity {
    const raw_host = if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']')
        host[1 .. host.len - 1]
    else
        host;
    const ip = std.Io.net.IpAddress.parse(raw_host, 0) catch return .{ .dns_name = host };
    return .{ .ip_address = switch (ip) {
        .ip4 => |value| .{ .v4 = value.bytes },
        .ip6 => |value| .{ .v6 = value.bytes },
    } };
}

test "TLS client invokes selected trust before accepting the peer public key" {
    const Reject = struct {
        calls: usize = 0,
        expected_adapter: ?*cert_crypto.CryptoCertificateVerifier = null,

        fn verify(context: *anyopaque, request: peer_trust.VerifyPeerRequest) peer_trust.TrustError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            if (self.expected_adapter) |adapter| {
                const expected = adapter.verifier();
                if (request.signature_verifier.context != expected.context or
                    request.signature_verifier.vtable != expected.vtable)
                    return error.TlsInvalidTrustConfiguration;
            }
            if (request.chain_der.len != 1 or
                !mem.eql(u8, request.chain_der[0], "\x30\x00") or
                !mem.eql(u8, request.expected_identity.?.dns_name, "localhost"))
                return error.TlsInvalidTrustConfiguration;
            return error.TlsUnknownCa;
        }
    };
    const server_hello = "\x16\x03\x03\x00\x2a\x02\x00\x00\x26\x03\x03".* ++
        @as([32]u8, @splat(0)) ++ "\x00\xc0\x2f\x00".*;
    const certificate = "\x16\x03\x03\x00\x0c\x0b\x00\x00\x08\x00\x00\x05\x00\x00\x02\x30\x00";
    var input_bytes: [min_buffer_len]u8 = @splat(0);
    @memcpy(input_bytes[0..server_hello.len], &server_hello);
    @memcpy(input_bytes[server_hello.len..][0..certificate.len], certificate);
    var output_bytes: [min_buffer_len]u8 = undefined;
    var application_read: [min_buffer_len]u8 = undefined;
    var application_write: [min_buffer_len]u8 = undefined;
    var input = Reader.fixed(&input_bytes);
    var output = Writer.fixed(&output_bytes);
    var standard = @import("crypto/standard.zig").StandardProvider.init(std.testing.io, std.testing.allocator);
    var adapter = cert_crypto.CryptoCertificateVerifier.init(standard.provider());
    var reject: Reject = .{};
    for ([_]bool{ false, true }) |bound| {
        reject.expected_adapter = if (bound) &adapter else null;
        input = Reader.fixed(&input_bytes);
        output = Writer.fixed(&output_bytes);
        try std.testing.expectError(error.TlsUnknownCa, init(&input, &output, .{
            .crypto_provider = standard.provider(),
            .certificate_crypto = if (bound) &adapter else null,
            .allocator = std.testing.allocator,
            .host = .{ .explicit = "localhost" },
            .trust_provider = .{ .context = &reject, .vtable = &.{ .verify_peer = Reject.verify } },
            .entropy = &@as([Options.entropy_len]u8, @splat(1)),
            .read_buffer = &application_read,
            .write_buffer = &application_write,
            .realtime_now = std.Io.Timestamp.now(std.testing.io, .real),
        }));
    }
    try std.testing.expectEqual(@as(usize, 2), reject.calls);
}

test "TLS raw client rejects a mismatched certificate adapter before I/O" {
    const Reject = struct {
        fn verify(_: *anyopaque, _: peer_trust.VerifyPeerRequest) peer_trust.TrustError!void {
            return error.TlsUnknownCa;
        }
    };
    var first = @import("crypto/standard.zig").StandardProvider.init(std.testing.io, std.testing.allocator);
    var second = @import("crypto/standard.zig").StandardProvider.init(std.testing.io, std.testing.allocator);
    var adapter = cert_crypto.CryptoCertificateVerifier.init(first.provider());
    var input_bytes: [min_buffer_len]u8 = @splat(0);
    var output_bytes: [min_buffer_len]u8 = undefined;
    var application_read: [min_buffer_len]u8 = undefined;
    var application_write: [min_buffer_len]u8 = undefined;
    var input = Reader.fixed(&input_bytes);
    var output = Writer.fixed(&output_bytes);
    var trust_context: u8 = 0;
    var options: Options = .{
        .crypto_provider = second.provider(),
        .certificate_crypto = &adapter,
        .allocator = std.testing.allocator,
        .host = .{ .explicit = "localhost" },
        .trust_provider = .{ .context = &trust_context, .vtable = &.{ .verify_peer = Reject.verify } },
        .entropy = &@as([Options.entropy_len]u8, @splat(1)),
        .read_buffer = &application_read,
        .write_buffer = &application_write,
        .realtime_now = std.Io.Timestamp.now(std.testing.io, .real),
    };
    try std.testing.expectError(error.TlsInvalidTrustConfiguration, init(&input, &output, options));
    try std.testing.expectEqual(@as(usize, 0), output.end);
    options.crypto_provider = first.provider();
    options.trust_provider = null;
    try std.testing.expectError(error.TlsInvalidTrustConfiguration, init(&input, &output, options));
    try std.testing.expectEqual(@as(usize, 0), output.end);
    options.trust_provider = .{ .context = &trust_context, .vtable = &.{ .verify_peer = Reject.verify } };
    options.host = .no_verification;
    try std.testing.expectError(error.TlsInvalidTrustConfiguration, init(&input, &output, options));
    try std.testing.expectEqual(@as(usize, 0), output.end);
}

test "TLS peer identity keeps IP literals distinct from DNS names" {
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &peerIdentity("127.0.0.1").ip_address.v4);
    try std.testing.expectEqual(@as(u8, 1), peerIdentity("::1").ip_address.v6[15]);
    try std.testing.expectEqual(@as(u8, 1), peerIdentity("[::1]").ip_address.v6[15]);
    try std.testing.expectEqualStrings("localhost", peerIdentity("localhost").dns_name);
}

test "ALPN ClientHello extension uses RFC 7301 u16 ProtocolNameList length" {
    var buffer: [64]u8 = undefined;
    const encoded = try buildAlpnExtension(&.{ "h2", "http/1.1" }, &buffer);
    const standard_vector = [_]u8{
        0x00, 0x10, 0x00, 0x0e,
        0x00, 0x0c, 0x02, 'h',
        '2',  0x08, 'h',  't',
        't',  'p',  '/',  '1',
        '.',  '1',
    };
    try std.testing.expectEqualSlices(u8, &standard_vector, encoded);
    try std.testing.expectError(
        error.TlsIllegalParameter,
        buildAlpnExtension(&.{""}, &buffer),
    );
}

test "ALPN selected protocol parses standard ServerHello vectors" {
    const h2 = [_]u8{ 0x00, 0x03, 0x02, 'h', '2' };
    try std.testing.expectEqualStrings("h2", try parseSelectedAlpnProtocol(&h2));

    const http1 = [_]u8{ 0x00, 0x09, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    try std.testing.expectEqualStrings("http/1.1", try parseSelectedAlpnProtocol(&http1));

    const malformed_one_byte_length = [_]u8{ 0x02, 'h', '2' };
    try std.testing.expectError(
        error.TlsDecodeError,
        parseSelectedAlpnProtocol(&malformed_one_byte_length),
    );
    const empty_protocol = [_]u8{ 0x00, 0x01, 0x00 };
    try std.testing.expectError(
        error.TlsIllegalParameter,
        parseSelectedAlpnProtocol(&empty_protocol),
    );
    try std.testing.expectError(
        error.TlsIllegalParameter,
        validateSelectedAlpnProtocol("h3", &.{ "h2", "http/1.1" }),
    );
}
