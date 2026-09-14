const std = @import("std");
const tls = std.crypto.tls;
const p = @import("crypto/provider.zig");
const state = @import("crypto/tls_state.zig");
const record = @import("crypto/record.zig");
const engine = @import("tls.zig");
const Socket = @import("../net/socket.zig").Socket;
const io_util = @import("../io/any_io.zig");
const alpn = @import("alpn.zig");
const Identity = @import("server_identity.zig").Identity;
const io_context = @import("../io/context.zig");
const IoContext = io_context.IoContext;
const HandshakeIoOptions = @import("server.zig").HandshakeIoOptions;

const max_plaintext = 16384;
const max_message = max_plaintext + 4;
const hybrid_group: u16 = 0x11ec;

fn List(comptime T: type, comptime capacity: usize) type {
    return struct {
        items: [capacity]T = undefined,
        len: usize = 0,

        fn append(self: *@This(), value: T) !void {
            if (self.len == capacity) return error.TlsIllegalParameter;
            self.items[self.len] = value;
            self.len += 1;
        }

        fn slice(self: *const @This()) []const T {
            return self.items[0..self.len];
        }
    };
}

const Decoder = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn take(self: *Decoder, length: usize) ![]const u8 {
        if (length > self.bytes.len - self.offset) return error.TlsDecodeError;
        defer self.offset += length;
        return self.bytes[self.offset..][0..length];
    }

    fn byte(self: *Decoder) !u8 {
        return (try self.take(1))[0];
    }

    fn short(self: *Decoder) !u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
    }

    fn vector8(self: *Decoder) ![]const u8 {
        return self.take(try self.byte());
    }

    fn vector16(self: *Decoder) ![]const u8 {
        return self.take(try self.short());
    }

    fn finish(self: Decoder) !void {
        if (self.offset != self.bytes.len) return error.TlsDecodeError;
    }
};

const Encoder = struct {
    bytes: []u8,
    offset: usize = 0,

    fn put(self: *Encoder, bytes: []const u8) !void {
        if (bytes.len > self.bytes.len - self.offset) return error.TlsRecordOverflow;
        @memcpy(self.bytes[self.offset..][0..bytes.len], bytes);
        self.offset += bytes.len;
    }

    fn byte(self: *Encoder, value: u8) !void {
        try self.put(&.{value});
    }

    fn short(self: *Encoder, value: usize) !void {
        if (value > 65535) return error.TlsRecordOverflow;
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @intCast(value), .big);
        try self.put(&bytes);
    }

    fn triple(self: *Encoder, value: usize) !void {
        if (value > 0xffffff) return error.TlsRecordOverflow;
        var bytes: [3]u8 = undefined;
        std.mem.writeInt(u24, &bytes, @intCast(value), .big);
        try self.put(&bytes);
    }

    fn vector8(self: *Encoder, bytes: []const u8) !void {
        if (bytes.len > 255) return error.TlsRecordOverflow;
        try self.byte(@intCast(bytes.len));
        try self.put(bytes);
    }

    fn vector16(self: *Encoder, bytes: []const u8) !void {
        try self.short(bytes.len);
        try self.put(bytes);
    }

    fn handshake(self: *Encoder, kind: u8) !void {
        try self.put(&.{ kind, 0, 0, 0 });
    }

    fn finish(self: *Encoder) ![]const u8 {
        if (self.offset < 4 or self.offset - 4 > 0xffffff) return error.TlsRecordOverflow;
        std.mem.writeInt(u24, self.bytes[1..4], @intCast(self.offset - 4), .big);
        return self.bytes[0..self.offset];
    }
};

const Share = struct { group: u16, key: []const u8 };
const Hello = struct {
    random: [32]u8,
    session_id: []const u8,
    suites: List(u16, 256) = .{},
    groups: List(u16, 128) = .{},
    signatures: List(u16, 128) = .{},
    shares: List(Share, 16) = .{},
    protocols: List([]const u8, 16) = .{},
    hostname: ?[]const u8 = null,
    tls13: bool = false,
    tls12: bool = true,
    ems: bool = false,
    secure_renegotiation: bool = false,
    point_formats: bool = false,
};

fn contains(values: []const u16, value: u16) bool {
    return std.mem.indexOfScalar(u16, values, value) != null;
}

fn parseHello(message: []const u8) !Hello {
    if (message.len < 4 or message[0] != 1 or
        std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.TlsDecodeError;
    var decoder: Decoder = .{ .bytes = message[4..] };
    if (try decoder.short() != 0x0303) return error.TlsIllegalParameter;
    var hello: Hello = .{
        .random = (try decoder.take(32))[0..32].*,
        .session_id = try decoder.vector8(),
    };
    if (hello.session_id.len > 32) return error.TlsIllegalParameter;
    var suites: Decoder = .{ .bytes = try decoder.vector16() };
    if (suites.bytes.len == 0 or suites.bytes.len % 2 != 0) return error.TlsDecodeError;
    while (suites.offset < suites.bytes.len) {
        const suite = try suites.short();
        if (suite == 0x00ff) hello.secure_renegotiation = true;
        try hello.suites.append(suite);
    }
    const compression = try decoder.vector8();
    if (std.mem.indexOfScalar(u8, compression, 0) == null) return error.TlsIllegalParameter;
    var extensions: Decoder = .{ .bytes = if (decoder.offset == decoder.bytes.len) "" else try decoder.vector16() };
    try decoder.finish();
    var seen: List(u16, 128) = .{};
    while (extensions.offset < extensions.bytes.len) {
        const kind = try extensions.short();
        const content = try extensions.vector16();
        if (contains(seen.slice(), kind)) return error.TlsIllegalParameter;
        try seen.append(kind);
        var extension: Decoder = .{ .bytes = content };
        switch (kind) {
            0 => {
                var names: Decoder = .{ .bytes = try extension.vector16() };
                if (try names.byte() != 0) return error.TlsIllegalParameter;
                const name = try names.vector16();
                if (name.len == 0 or name.len > 253) return error.TlsIllegalParameter;
                for (name) |byte| {
                    if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '.') return error.TlsIllegalParameter;
                }
                try names.finish();
                hello.hostname = name;
            },
            10, 13 => {
                var values: Decoder = .{ .bytes = try extension.vector16() };
                if (values.bytes.len == 0 or values.bytes.len % 2 != 0) return error.TlsDecodeError;
                while (values.offset < values.bytes.len) {
                    const value = try values.short();
                    if (kind == 10) try hello.groups.append(value) else try hello.signatures.append(value);
                }
            },
            11 => {
                const formats = try extension.vector8();
                if (std.mem.indexOfScalar(u8, formats, 0) == null) return error.TlsIllegalParameter;
                hello.point_formats = true;
            },
            16 => {
                var protocols: Decoder = .{ .bytes = try extension.vector16() };
                if (protocols.bytes.len == 0) return error.TlsDecodeError;
                while (protocols.offset < protocols.bytes.len) {
                    const protocol = try protocols.vector8();
                    if (protocol.len == 0) return error.TlsIllegalParameter;
                    try hello.protocols.append(protocol);
                }
            },
            23 => hello.ems = true,
            42 => return error.TlsUnexpectedMessage, // Early data is not implemented.
            43 => {
                var versions: Decoder = .{ .bytes = try extension.vector8() };
                if (versions.bytes.len == 0 or versions.bytes.len % 2 != 0) return error.TlsDecodeError;
                hello.tls12 = false;
                while (versions.offset < versions.bytes.len) {
                    switch (try versions.short()) {
                        0x0303 => hello.tls12 = true,
                        0x0304 => hello.tls13 = true,
                        else => {},
                    }
                }
            },
            51 => {
                var shares: Decoder = .{ .bytes = try extension.vector16() };
                while (shares.offset < shares.bytes.len) {
                    const group = try shares.short();
                    const key = try shares.vector16();
                    if (key.len == 0) return error.TlsIllegalParameter;
                    for (hello.shares.slice()) |share| if (share.group == group) return error.TlsIllegalParameter;
                    try hello.shares.append(.{ .group = group, .key = key });
                }
            },
            0xff01 => {
                if ((try extension.vector8()).len != 0) return error.TlsIllegalParameter;
                hello.secure_renegotiation = true;
            },
            else => continue,
        }
        try extension.finish();
    }
    if (hello.tls13 and !std.mem.eql(u8, compression, "\x00")) return error.TlsIllegalParameter;
    var previous_group: ?usize = null;
    for (hello.shares.slice()) |share| {
        const position = std.mem.indexOfScalar(u16, hello.groups.slice(), share.group) orelse return error.TlsIllegalParameter;
        if (previous_group) |previous| if (position <= previous) return error.TlsIllegalParameter;
        previous_group = position;
    }
    return hello;
}

const Keys = struct { key: [32]u8 = @splat(0), iv: [12]u8 = @splat(0) };
const Epoch = struct { keys: Keys, sequence: u64 = 0 };

fn Wire(comptime Transport: type) type {
    return struct {
        const Self = @This();
        socket: *Transport,
        provider: p.CryptoProvider,
        io_options: ?HandshakeIoOptions = null,
        version: tls.ProtocolVersion = .tls_1_2,
        suite: tls.CipherSuite = .AES_128_GCM_SHA256,
        read_epoch: ?Epoch = null,
        write_epoch: ?Epoch = null,
        record_buffer: [max_plaintext + 256]u8 = undefined,
        pending: [max_message]u8 = undefined,
        start: usize = 0,
        end: usize = 0,
        initial: bool = true,
        skipped_ccs: usize = 0,

        fn operationContext(self: *const Self, comptime direction: enum { read, write }) ?IoContext {
            const options = self.io_options orelse return null;
            const budget = if (direction == .read) options.read_timeout_ms else options.write_timeout_ms;
            return IoContext.init(.{
                .parent = options.context,
                .phase_deadline = if (budget) |ms| io_context.Deadline.afterMs(ms) else null,
            });
        }

        fn receiveAll(self: *Self, out: []u8, context: ?*const IoContext) !void {
            if (context) |ctx| try ctx.check();
            var offset: usize = 0;
            while (offset < out.len) {
                if (context) |ctx| try ctx.check();
                const result = if (context) |ctx|
                    self.socket.recvWithContext(out[offset..], ctx)
                else
                    self.socket.recv(out[offset..]);
                const count = if (context) |ctx| try ctx.unwrapAfterBlocking(usize, result) else try result;
                if (count == 0) return error.UnexpectedEof;
                offset += count;
            }
        }

        fn receiveRecord(self: *Self, context: ?*const IoContext) !struct { kind: u8, bytes: []const u8 } {
            var header: [5]u8 = undefined;
            try self.receiveAll(&header, context);
            if (header[1] != 3 or header[2] > 3 or header[2] < (if (self.initial) @as(u8, 1) else 3))
                return error.TlsIllegalParameter;
            const length = std.mem.readInt(u16, header[3..5], .big);
            if (length > self.record_buffer.len) return error.TlsRecordOverflow;
            const body = self.record_buffer[0..length];
            try self.receiveAll(body, context);
            if (self.read_epoch) |*epoch| {
                if (self.version == .tls_1_3 and header[0] == 20) {
                    if (!std.mem.eql(u8, body, "\x01") or self.skipped_ccs == 8) return error.TlsUnexpectedMessage;
                    self.skipped_ccs += 1;
                    return .{ .kind = 20, .bytes = body };
                }
                if (self.version == .tls_1_3 and header[0] != 23) return error.TlsUnexpectedMessage;
                const next_sequence = std.math.add(u64, epoch.sequence, 1) catch return error.TlsSequenceOverflow;
                const opened = record.open(self.provider, self.version, self.suite, body, &header, &epoch.keys.key, &epoch.keys.iv, epoch.sequence);
                var plaintext = if (context) |ctx| try ctx.unwrapAfterBlocking([]u8, opened) else try opened;
                epoch.sequence = next_sequence;
                var kind = header[0];
                if (self.version == .tls_1_3) {
                    while (plaintext.len != 0 and plaintext[plaintext.len - 1] == 0) plaintext = plaintext[0 .. plaintext.len - 1];
                    if (plaintext.len == 0) return error.TlsDecodeError;
                    kind = plaintext[plaintext.len - 1];
                    plaintext = plaintext[0 .. plaintext.len - 1];
                }
                if (plaintext.len > max_plaintext) return error.TlsRecordOverflow;
                return .{ .kind = kind, .bytes = plaintext };
            }
            if (length > max_plaintext) return error.TlsRecordOverflow;
            return .{ .kind = header[0], .bytes = body };
        }

        fn next(self: *Self, expected: u8) ![]const u8 {
            var phase = self.operationContext(.read);
            const context = if (phase) |*ctx| ctx else null;
            var empty_records: usize = 0;
            while (true) {
                if (context) |ctx| try ctx.check();
                const available = self.end - self.start;
                if (available >= 4) {
                    const length = 4 + @as(usize, std.mem.readInt(u24, self.pending[self.start + 1 ..][0..3], .big));
                    if (length > self.pending.len) return error.TlsRecordOverflow;
                    if (available >= length) {
                        const message = self.pending[self.start..][0..length];
                        if (message[0] != expected) return error.TlsUnexpectedMessage;
                        self.start += length;
                        self.initial = false;
                        return message;
                    }
                }
                if (self.start != 0) {
                    std.mem.copyForwards(u8, self.pending[0..available], self.pending[self.start..self.end]);
                    self.start = 0;
                    self.end = available;
                }
                const incoming = try self.receiveRecord(context);
                if (incoming.kind == 20 and self.version == .tls_1_3 and self.read_epoch != null) continue;
                if (incoming.kind == 21) return error.TlsAlert;
                if (incoming.kind != 22) return error.TlsUnexpectedMessage;
                if (incoming.bytes.len == 0) {
                    empty_records += 1;
                    if (empty_records == 32) return error.TlsUnexpectedMessage;
                    continue;
                }
                if (incoming.bytes.len > self.pending.len - self.end) return error.TlsRecordOverflow;
                @memcpy(self.pending[self.end..][0..incoming.bytes.len], incoming.bytes);
                self.end += incoming.bytes.len;
            }
        }

        fn requireBoundary(self: *Self) !void {
            if (self.start != self.end) return error.TlsUnexpectedMessage;
            self.start = 0;
            self.end = 0;
        }

        fn expectCcs(self: *Self) !void {
            var phase = self.operationContext(.read);
            const context = if (phase) |*ctx| ctx else null;
            if (context) |ctx| try ctx.check();
            try self.requireBoundary();
            const incoming = try self.receiveRecord(context);
            if (incoming.kind != 20 or !std.mem.eql(u8, incoming.bytes, "\x01")) return error.TlsUnexpectedMessage;
        }

        fn enableRead(self: *Self, keys: Keys) !void {
            try self.requireBoundary();
            self.read_epoch = .{ .keys = keys };
        }

        fn sendRecord(self: *Self, kind: u8, plaintext: []const u8) !void {
            var phase = self.operationContext(.write);
            return self.sendRecordWithContext(kind, plaintext, if (phase) |*ctx| ctx else null);
        }

        fn sendPacket(self: *Self, packet: []const u8, context: ?*const IoContext) !void {
            if (context) |ctx| {
                try ctx.check();
                const result = self.socket.sendAllWithContext(packet, ctx);
                return ctx.unwrapAfterBlocking(void, result);
            }
            return self.socket.sendAll(packet);
        }

        fn sendRecordWithContext(self: *Self, kind: u8, plaintext: []const u8, context: ?*const IoContext) !void {
            if (context) |ctx| try ctx.check();
            if (plaintext.len > max_plaintext) return error.TlsRecordOverflow;
            var packet: [max_plaintext + 256 + 5]u8 = undefined;
            defer p.secureWipe(&packet);
            packet[0] = kind;
            packet[1] = 3;
            packet[2] = 3;
            if (self.write_epoch) |*epoch| {
                var inner: [max_plaintext + 1]u8 = undefined;
                defer p.secureWipe(&inner);
                @memcpy(inner[0..plaintext.len], plaintext);
                var inner_length = plaintext.len;
                if (self.version == .tls_1_3) {
                    inner[inner_length] = kind;
                    inner_length += 1;
                    packet[0] = 23;
                }
                const explicit_nonce: usize = if (self.version == .tls_1_2 and profile(self.suite).aead != .chacha20_poly1305) 8 else 0;
                std.mem.writeInt(u16, packet[3..5], @intCast(inner_length + explicit_nonce + 16), .big);
                const next_sequence = std.math.add(u64, epoch.sequence, 1) catch return error.TlsSequenceOverflow;
                const sealed = record.seal(self.provider, self.version, self.suite, packet[5..], inner[0..inner_length], packet[0..5], &epoch.keys.key, &epoch.keys.iv, epoch.sequence) catch |err| {
                    if (context) |ctx| try ctx.check();
                    return err;
                };
                epoch.sequence = next_sequence;
                try self.sendPacket(packet[0 .. 5 + sealed.len], context);
            } else {
                std.mem.writeInt(u16, packet[3..5], @intCast(plaintext.len), .big);
                @memcpy(packet[5..][0..plaintext.len], plaintext);
                try self.sendPacket(packet[0 .. 5 + plaintext.len], context);
            }
        }

        fn send(self: *Self, transcript: anytype, message: []const u8) !void {
            var phase = self.operationContext(.write);
            const context = if (phase) |*ctx| ctx else null;
            if (context) |ctx| try ctx.check();
            const updated = transcript.update(message);
            if (context) |ctx| try ctx.unwrapAfterBlocking(void, updated) else try updated;
            var offset: usize = 0;
            while (offset < message.len) {
                const length = @min(max_plaintext, message.len - offset);
                try self.sendRecordWithContext(22, message[offset..][0..length], context);
                offset += length;
            }
        }
    };
}

const Profile = struct { aead: p.AeadAlgorithm, hash: p.HashAlgorithm };

fn profile(suite: tls.CipherSuite) Profile {
    return switch (suite) {
        .AES_128_GCM_SHA256, .ECDHE_RSA_WITH_AES_128_GCM_SHA256, .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => .{ .aead = .aes_128_gcm, .hash = .sha256 },
        .AES_256_GCM_SHA384, .ECDHE_RSA_WITH_AES_256_GCM_SHA384, .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => .{ .aead = .aes_256_gcm, .hash = .sha384 },
        .CHACHA20_POLY1305_SHA256, .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => .{ .aead = .chacha20_poly1305, .hash = .sha256 },
        else => unreachable,
    };
}

fn selectSuite(hello: *const Hello, caps: p.Capabilities, identity: *const Identity, version: tls.ProtocolVersion) !tls.CipherSuite {
    const rsa = identity.key.algorithm == .rsa or identity.key.algorithm == .rsa_pss;
    const suites13 = [_]tls.CipherSuite{ .CHACHA20_POLY1305_SHA256, .AES_128_GCM_SHA256, .AES_256_GCM_SHA384 };
    const rsa12 = [_]tls.CipherSuite{ .ECDHE_RSA_WITH_AES_128_GCM_SHA256, .ECDHE_RSA_WITH_AES_256_GCM_SHA384, .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 };
    const ec12 = [_]tls.CipherSuite{ .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 };
    const candidates = if (version == .tls_1_3) &suites13 else if (rsa) &rsa12 else &ec12;
    for (candidates) |suite| {
        const algorithms = profile(suite);
        if (!contains(hello.suites.slice(), @intFromEnum(suite)) or !caps.supportsAead(algorithms.aead) or
            !caps.supportsHash(algorithms.hash)) continue;
        if (version == .tls_1_3) {
            if (!caps.supportsHkdf(algorithms.hash) or !caps.supportsHmac(algorithms.hash)) continue;
        } else if (!caps.supportsTls12Prf(algorithms.hash)) continue;
        return suite;
    }
    return error.TlsUnsupportedCipherSuite;
}

fn selectSignature(hello: *const Hello, identity: *const Identity, version: tls.ProtocolVersion) !p.SignatureScheme {
    const preferences = [_]p.SignatureScheme{
        .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384, .ed25519,
        .rsa_pss_rsae_sha256,    .rsa_pss_rsae_sha384,    .rsa_pss_rsae_sha512,
        .rsa_pss_pss_sha256,     .rsa_pss_pss_sha384,     .rsa_pss_pss_sha512,
        .rsa_pkcs1_sha256,       .rsa_pkcs1_sha384,       .rsa_pkcs1_sha512,
    };
    for (preferences) |scheme| {
        if (version == .tls_1_3 and switch (scheme) {
            .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 => true,
            else => false,
        }) continue;
        if (version == .tls_1_2) {
            const curve: ?u16 = switch (scheme) {
                .ecdsa_secp256r1_sha256 => 23,
                .ecdsa_secp384r1_sha384 => 24,
                else => null,
            };
            if (curve) |group| if (!contains(hello.groups.slice(), group)) continue;
        }
        if (identity.supports(scheme) and contains(hello.signatures.slice(), @intFromEnum(scheme))) return scheme;
    }
    return error.UnsupportedAlgorithm;
}

fn groupAlgorithm(group: u16) ?p.KeyAgreementAlgorithm {
    return switch (group) {
        29, hybrid_group => .x25519,
        23 => .secp256r1,
        24 => .secp384r1,
        else => null,
    };
}

fn selectGroup(hello: *const Hello, caps: p.Capabilities, version: tls.ProtocolVersion) !u16 {
    for ([_]u16{ hybrid_group, 29, 23, 24 }) |group| {
        if (group == hybrid_group and (version != .tls_1_3 or !caps.supportsKem(.ml_kem_768))) continue;
        if (!caps.supportsKeyAgreement(groupAlgorithm(group).?) or !contains(hello.groups.slice(), group)) continue;
        if (version == .tls_1_2) return group;
        for (hello.shares.slice()) |share| if (share.group == group) return group;
    }
    return error.TlsKeyExchangeFailed;
}

fn appendAlpn(encoder: *Encoder, protocol: []const u8) !void {
    try encoder.short(16);
    try encoder.short(protocol.len + 3);
    try encoder.short(protocol.len + 1);
    try encoder.vector8(protocol);
}

fn serverHello(out: []u8, hello: *const Hello, version: tls.ProtocolVersion, suite: tls.CipherSuite, random: *const [32]u8, group: u16, share: []const u8, protocol: ?[]const u8) ![]const u8 {
    var extension_buffer: [1536]u8 = undefined;
    var extensions: Encoder = .{ .bytes = &extension_buffer };
    if (version == .tls_1_3) {
        try extensions.short(43);
        try extensions.short(2);
        try extensions.short(0x0304);
        try extensions.short(51);
        try extensions.short(4 + share.len);
        try extensions.short(group);
        try extensions.vector16(share);
    } else {
        if (hello.secure_renegotiation) try extensions.put("\xff\x01\x00\x01\x00");
        if (hello.ems) try extensions.put("\x00\x17\x00\x00");
        if (hello.point_formats) try extensions.put("\x00\x0b\x00\x02\x01\x00");
        if (protocol) |name| try appendAlpn(&extensions, name);
    }
    var encoder: Encoder = .{ .bytes = out };
    try encoder.handshake(2);
    try encoder.short(0x0303);
    try encoder.put(random);
    try encoder.vector8(if (version == .tls_1_3) hello.session_id else "");
    try encoder.short(@intFromEnum(suite));
    try encoder.byte(0);
    try encoder.vector16(extension_buffer[0..extensions.offset]);
    return encoder.finish();
}

fn certificateMessage(allocator: std.mem.Allocator, certificates: []const []const u8, version: tls.ProtocolVersion) ![]u8 {
    var list_length: usize = 0;
    for (certificates) |certificate| list_length += certificate.len + 3 + @as(usize, if (version == .tls_1_3) 2 else 0);
    const length = 4 + 3 + list_length + @as(usize, if (version == .tls_1_3) 1 else 0);
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    var encoder: Encoder = .{ .bytes = bytes };
    try encoder.handshake(11);
    if (version == .tls_1_3) try encoder.byte(0);
    try encoder.triple(list_length);
    for (certificates) |certificate| {
        try encoder.triple(certificate.len);
        try encoder.put(certificate);
        if (version == .tls_1_3) try encoder.short(0);
    }
    _ = try encoder.finish();
    return bytes;
}

fn trafficKeys(provider: p.CryptoProvider, comptime hash: p.HashAlgorithm, secret: [hash.digestLength()]u8, suite: tls.CipherSuite) !Keys {
    const K = state.HkdfType(hash);
    var keys: Keys = .{};
    errdefer p.secureWipeValue(&keys);
    if (profile(suite).aead == .aes_128_gcm) {
        var short_key = try state.hkdfExpandLabel(provider, K, secret, "key", "", 16);
        defer p.secureWipe(&short_key);
        @memcpy(keys.key[0..16], &short_key);
    } else keys.key = try state.hkdfExpandLabel(provider, K, secret, "key", "", 32);
    keys.iv = try state.hkdfExpandLabel(provider, K, secret, "iv", "", 12);
    return keys;
}

fn handshake13(comptime hash: p.HashAlgorithm, conn: *engine.Connection, wire: *Wire(Socket), hello: *const Hello, client_message: []const u8, config: engine.ServerTLSConfig, identity: *Identity, signature_scheme: p.SignatureScheme, group: u16) !void {
    const provider = wire.provider;
    const H = state.HashType(hash);
    const K = state.HkdfType(hash);
    const size = H.digest_length;
    var transcript = try H.init(provider, conn.allocator);
    defer transcript.deinit();
    try transcript.update(client_message);
    try wire.requireBoundary();
    var agreement = try provider.keyAgreementGenerate(conn.allocator, groupAlgorithm(group).?);
    defer agreement.deinit();
    const peer = for (hello.shares.slice()) |share| {
        if (share.group == group) break share.key;
    } else return error.TlsKeyExchangeFailed;
    var shared: [64]u8 = undefined;
    defer p.secureWipe(&shared);
    var public: [1120]u8 = undefined;
    var public_length: usize = undefined;
    var shared_length: usize = undefined;
    if (group == hybrid_group) {
        if (peer.len != 1216) return error.TlsKeyExchangeFailed;
        try provider.kemEncapsulate(.ml_kem_768, peer[0..1184], public[0..1088], shared[0..32]);
        try agreement.publicKey(public[1088..1120]);
        try agreement.agree(peer[1184..1216], shared[32..64]);
        public_length = 1120;
        shared_length = 64;
    } else {
        public_length = agreement.algorithm.publicKeyLength();
        shared_length = agreement.algorithm.sharedSecretLength();
        try agreement.publicKey(public[0..public_length]);
        try agreement.agree(peer, shared[0..shared_length]);
    }
    var random: [32]u8 = undefined;
    try provider.random(&random);
    var message_buffer: [2048]u8 = undefined;
    const sh = try serverHello(&message_buffer, hello, .tls_1_3, wire.suite, &random, group, public[0..public_length], null);
    try wire.send(&transcript, sh);
    if (hello.session_id.len != 0) try wire.sendRecord(20, "\x01");
    const zeros: [size]u8 = @splat(0);
    var empty_hash = try state.emptyHash(provider, conn.allocator, H);
    defer p.secureWipe(&empty_hash);
    var early = try K.extract(provider, &zeros, &zeros);
    defer p.secureWipe(&early);
    var derived_early = try state.hkdfExpandLabel(provider, K, early, "derived", &empty_hash, size);
    defer p.secureWipe(&derived_early);
    var handshake_secret = try K.extract(provider, &derived_early, shared[0..shared_length]);
    defer p.secureWipe(&handshake_secret);
    const hello_hash = try transcript.peek();
    var server_secret = try state.hkdfExpandLabel(provider, K, handshake_secret, "s hs traffic", &hello_hash, size);
    defer p.secureWipe(&server_secret);
    var client_secret = try state.hkdfExpandLabel(provider, K, handshake_secret, "c hs traffic", &hello_hash, size);
    defer p.secureWipe(&client_secret);
    var server_keys = try trafficKeys(provider, hash, server_secret, wire.suite);
    defer p.secureWipeValue(&server_keys);
    var client_keys = try trafficKeys(provider, hash, client_secret, wire.suite);
    defer p.secureWipeValue(&client_keys);
    wire.write_epoch = .{ .keys = server_keys };

    var extension_buffer: [512]u8 = undefined;
    var extensions: Encoder = .{ .bytes = &extension_buffer };
    if (conn.negotiatedAlpn()) |name| try appendAlpn(&extensions, name);
    var ee: Encoder = .{ .bytes = &message_buffer };
    try ee.handshake(8);
    try ee.vector16(extension_buffer[0..extensions.offset]);
    try wire.send(&transcript, try ee.finish());
    const certificates = try certificateMessage(conn.allocator, config.cert_chain_der, .tls_1_3);
    defer conn.allocator.free(certificates);
    try wire.send(&transcript, certificates);
    const certificate_hash = try transcript.peek();
    var signature_buffer: [512]u8 = undefined;
    const signature = try identity.sign(io_util.threadIo(), signature_scheme, &.{
        &@as([64]u8, @splat(32)), "TLS 1.3, server CertificateVerify\x00", &certificate_hash,
    }, &signature_buffer);
    var cv: Encoder = .{ .bytes = &message_buffer };
    try cv.handshake(15);
    try cv.short(@intFromEnum(signature_scheme));
    try cv.vector16(signature);
    try wire.send(&transcript, try cv.finish());
    var server_finished_key = try state.hkdfExpandLabel(provider, K, server_secret, "finished", "", size);
    defer p.secureWipe(&server_finished_key);
    const before_finished = try transcript.peek();
    var verify: [size]u8 = undefined;
    defer p.secureWipe(&verify);
    try provider.hmac(hash, &server_finished_key, &.{&before_finished}, &verify);
    var finished: Encoder = .{ .bytes = &message_buffer };
    try finished.handshake(20);
    try finished.put(&verify);
    try wire.send(&transcript, try finished.finish());
    const application_hash = try transcript.peek();

    try wire.enableRead(client_keys);
    const client_finished = try wire.next(20);
    if (client_finished.len != 4 + size) return error.TlsDecodeError;
    var client_finished_key = try state.hkdfExpandLabel(provider, K, client_secret, "finished", "", size);
    defer p.secureWipe(&client_finished_key);
    try provider.hmac(hash, &client_finished_key, &.{&application_hash}, &verify);
    if (!try provider.constantTimeEqual(client_finished[4..], &verify)) return error.TlsDecryptError;
    try transcript.update(client_finished);
    try wire.requireBoundary();

    var derived_handshake = try state.hkdfExpandLabel(provider, K, handshake_secret, "derived", &empty_hash, size);
    defer p.secureWipe(&derived_handshake);
    var master = try K.extract(provider, &derived_handshake, &zeros);
    defer p.secureWipe(&master);
    var server_application = try state.hkdfExpandLabel(provider, K, master, "s ap traffic", &application_hash, size);
    defer p.secureWipe(&server_application);
    var client_application = try state.hkdfExpandLabel(provider, K, master, "c ap traffic", &application_hash, size);
    defer p.secureWipe(&client_application);
    var server_application_keys = try trafficKeys(provider, hash, server_application, wire.suite);
    defer p.secureWipeValue(&server_application_keys);
    var client_application_keys = try trafficKeys(provider, hash, client_application, wire.suite);
    defer p.secureWipeValue(&client_application_keys);
    conn.app_write_key = server_application_keys.key;
    conn.app_write_iv = server_application_keys.iv;
    conn.app_read_key = client_application_keys.key;
    conn.app_read_iv = client_application_keys.iv;
    conn.app_write_secret = @splat(0);
    conn.app_read_secret = @splat(0);
    @memcpy(conn.app_write_secret.?[0..size], &server_application);
    @memcpy(conn.app_read_secret.?[0..size], &client_application);
    conn.hs_read_seq = wire.read_epoch.?.sequence;
    conn.hs_write_seq = wire.write_epoch.?.sequence;
}

fn handshake12(comptime hash: p.HashAlgorithm, conn: *engine.Connection, wire: *Wire(Socket), hello: *const Hello, client_message: []const u8, config: engine.ServerTLSConfig, identity: *Identity, signature_scheme: p.SignatureScheme, group: u16) !void {
    const provider = wire.provider;
    const H = state.HashType(hash);
    var transcript = try H.init(provider, conn.allocator);
    defer transcript.deinit();
    try transcript.update(client_message);
    try wire.requireBoundary();
    var server_random: [32]u8 = undefined;
    try provider.random(&server_random);
    @memcpy(server_random[24..32], "DOWNGRD\x01");
    var message_buffer: [2048]u8 = undefined;
    const sh = try serverHello(&message_buffer, hello, .tls_1_2, wire.suite, &server_random, group, "", conn.negotiatedAlpn());
    try wire.send(&transcript, sh);
    const certificates = try certificateMessage(conn.allocator, config.cert_chain_der, .tls_1_2);
    defer conn.allocator.free(certificates);
    try wire.send(&transcript, certificates);
    var agreement = try provider.keyAgreementGenerate(conn.allocator, groupAlgorithm(group).?);
    defer agreement.deinit();
    var public_buffer: [97]u8 = undefined;
    const public = public_buffer[0..agreement.algorithm.publicKeyLength()];
    try agreement.publicKey(public);
    var params_buffer: [101]u8 = undefined;
    var params: Encoder = .{ .bytes = &params_buffer };
    try params.byte(3);
    try params.short(group);
    try params.vector8(public);
    var signature_buffer: [512]u8 = undefined;
    const signature = try identity.sign(io_util.threadIo(), signature_scheme, &.{
        &hello.random, &server_random, params_buffer[0..params.offset],
    }, &signature_buffer);
    var ske: Encoder = .{ .bytes = &message_buffer };
    try ske.handshake(12);
    try ske.put(params_buffer[0..params.offset]);
    try ske.short(@intFromEnum(signature_scheme));
    try ske.vector16(signature);
    try wire.send(&transcript, try ske.finish());
    try wire.send(&transcript, "\x0e\x00\x00\x00");

    const client_key_exchange = try wire.next(16);
    var exchange: Decoder = .{ .bytes = client_key_exchange[4..] };
    const peer = try exchange.vector8();
    try exchange.finish();
    var shared: [48]u8 = undefined;
    defer p.secureWipe(&shared);
    const shared_length = agreement.algorithm.sharedSecretLength();
    try agreement.agree(peer, shared[0..shared_length]);
    try transcript.update(client_key_exchange);
    const before_finished = try transcript.peek();
    var master: [48]u8 = undefined;
    defer p.secureWipe(&master);
    if (hello.ems) {
        try provider.tls12Prf(hash, shared[0..shared_length], "extended master secret", &.{&before_finished}, &master);
    } else {
        try provider.tls12Prf(hash, shared[0..shared_length], "master secret", &.{ &hello.random, &server_random }, &master);
    }
    const algorithm = profile(wire.suite).aead;
    const key_length = algorithm.keyLength();
    const iv_length: usize = if (algorithm == .chacha20_poly1305) 12 else 4;
    var key_block: [88]u8 = undefined;
    defer p.secureWipe(&key_block);
    try provider.tls12Prf(hash, &master, "key expansion", &.{ &server_random, &hello.random }, key_block[0 .. 2 * (key_length + iv_length)]);
    var server_keys: Keys = .{};
    defer p.secureWipeValue(&server_keys);
    var client_keys: Keys = .{};
    defer p.secureWipeValue(&client_keys);
    @memcpy(client_keys.key[0..key_length], key_block[0..key_length]);
    @memcpy(server_keys.key[0..key_length], key_block[key_length..][0..key_length]);
    @memcpy(client_keys.iv[0..iv_length], key_block[2 * key_length ..][0..iv_length]);
    @memcpy(server_keys.iv[0..iv_length], key_block[2 * key_length + iv_length ..][0..iv_length]);
    try wire.expectCcs();
    try wire.enableRead(client_keys);
    const client_finished = try wire.next(20);
    if (client_finished.len != 16) return error.TlsDecodeError;
    var verify: [12]u8 = undefined;
    defer p.secureWipe(&verify);
    try provider.tls12Prf(hash, &master, "client finished", &.{&before_finished}, &verify);
    if (!try provider.constantTimeEqual(client_finished[4..], &verify)) return error.TlsDecryptError;
    try transcript.update(client_finished);
    try wire.requireBoundary();
    try wire.sendRecord(20, "\x01");
    wire.write_epoch = .{ .keys = server_keys };
    const full_hash = try transcript.peek();
    try provider.tls12Prf(hash, &master, "server finished", &.{&full_hash}, &verify);
    var finished: Encoder = .{ .bytes = &message_buffer };
    try finished.handshake(20);
    try finished.put(&verify);
    try wire.send(&transcript, try finished.finish());
    conn.app_write_key = server_keys.key;
    conn.app_write_iv = server_keys.iv;
    conn.app_read_key = client_keys.key;
    conn.app_read_iv = client_keys.iv;
    conn.write_seq = wire.write_epoch.?.sequence;
    conn.read_seq = wire.read_epoch.?.sequence;
}

pub fn accept(allocator: std.mem.Allocator, socket: *Socket, protocols: []const []const u8, server_config: ?engine.ServerTLSConfig) !engine.Connection {
    return acceptInternal(allocator, socket, protocols, server_config, null);
}

pub fn acceptWithIo(allocator: std.mem.Allocator, socket: *Socket, protocols: []const []const u8, server_config: ?engine.ServerTLSConfig, options: HandshakeIoOptions) !engine.Connection {
    try options.context.check();
    var connection = acceptInternal(allocator, socket, protocols, server_config, options) catch |err| {
        try options.context.check();
        return err;
    };
    errdefer connection.deinit();
    try options.context.check();
    return connection;
}

fn acceptInternal(allocator: std.mem.Allocator, socket: *Socket, protocols: []const []const u8, server_config: ?engine.ServerTLSConfig, options: ?HandshakeIoOptions) !engine.Connection {
    const config = server_config orelse return error.TlsInvalidPrivateKey;
    if (config.cert_chain_der.len == 0 or config.cert_chain_der.len > 16) return error.TlsNoCertificates;
    var total: usize = 0;
    for (config.cert_chain_der) |certificate| {
        if (certificate.len == 0 or certificate.len > 256 * 1024) return error.TlsRecordOverflow;
        total += certificate.len;
    }
    if (total > 256 * 1024) return error.TlsRecordOverflow;
    var local_identity: ?*Identity = null;
    defer if (local_identity) |identity| identity.destroy();
    const identity = config.identity orelse blk: {
        const public = try engine.certificate_crypto.certificatePublicKeyInfo(config.cert_chain_der[0]);
        const private: p.PrivateKey = if (config.key_der) |bytes| .{
            .algorithm = public.key.algorithm,
            .encoding = try @import("server_identity.zig").privateEncoding(public.key.algorithm, bytes),
            .bytes = bytes,
        } else if (config.ecdsa_keypair) |*pair| .{
            .algorithm = .ecdsa_p256,
            .encoding = .raw_secret,
            .bytes = &pair.secret_key.bytes,
        } else return error.TlsInvalidPrivateKey;
        local_identity = try Identity.create(allocator, io_util.threadIo(), config.crypto_provider, public.key, public.pss_parameters, private);
        break :blk local_identity.?;
    };
    if (config.crypto_provider) |selected| {
        if (identity.uses_standard or identity.crypto.context != selected.context or identity.crypto.vtable != selected.vtable or
            identity.crypto.abi_version != selected.abi_version) return error.TlsCryptoProviderMismatch;
    } else if (!identity.uses_standard) return error.TlsCryptoProviderMismatch;
    var conn: engine.Connection = .{
        .allocator = allocator,
        .socket = socket,
        .is_server = true,
        .connected = true,
        .crypto_provider = config.crypto_provider,
    };
    errdefer conn.deinit();
    const provider = conn.cryptoProvider();
    const capabilities = try provider.capabilities();
    if (!capabilities.random or !capabilities.constant_time_equal) return error.UnsupportedAlgorithm;
    var wire: Wire(Socket) = .{ .socket = socket, .provider = provider, .io_options = options };
    defer p.secureWipeValue(&wire);
    const client_message = try wire.next(1);
    const hello = try parseHello(client_message);
    const version: tls.ProtocolVersion = if (hello.tls13) .tls_1_3 else if (hello.tls12) .tls_1_2 else return error.TlsIllegalParameter;
    const suite = try selectSuite(&hello, capabilities, identity, version);
    const signature_scheme = try selectSignature(&hello, identity, version);
    const group = try selectGroup(&hello, capabilities, version);
    if (hello.hostname) |hostname| {
        conn.owned_sni_hostname = try allocator.dupe(u8, hostname);
        conn.sni_hostname = conn.owned_sni_hostname;
    }
    if (alpn.serverNegotiate(protocols, hello.protocols.slice())) |selected| {
        conn.negotiated_alpn.set(selected);
    } else if (protocols.len != 0 and hello.protocols.len != 0) return error.TlsNoApplicationProtocol;
    wire.version = version;
    wire.suite = suite;
    switch (profile(suite).hash) {
        inline .sha256, .sha384 => |hash| {
            if (version == .tls_1_3) {
                try handshake13(hash, &conn, &wire, &hello, client_message, config, identity, signature_scheme, group);
            } else {
                try handshake12(hash, &conn, &wire, &hello, client_message, config, identity, signature_scheme, group);
            }
        },
        else => unreachable,
    }
    conn.tls_version = version;
    conn.cipher_suite = suite;
    return conn;
}

test "server runtime rejects missing identity before transport access" {
    var socket: Socket = undefined;
    try std.testing.expectError(error.TlsInvalidPrivateKey, accept(std.testing.allocator, &socket, &.{"http/1.1"}, null));
}

fn helloFixture(out: []u8, extra_extensions: []const u8, session_id: []const u8) ![]const u8 {
    var extension_buffer: [512]u8 = undefined;
    var extensions: Encoder = .{ .bytes = &extension_buffer };
    try extensions.put("\x00\x00\x00\x0e\x00\x0c\x00\x00\x09localhost");
    try extensions.put("\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18");
    try extensions.put("\x00\x0d\x00\x0e\x00\x0c\x04\x03\x05\x03\x08\x04\x08\x09\x08\x07\x04\x01");
    try extensions.put("\x00\x2b\x00\x05\x04\x03\x04\x03\x03");
    try extensions.put("\x00\x17\x00\x00");
    try appendAlpn(&extensions, "http/1.1");
    try extensions.short(51);
    try extensions.short(38);
    try extensions.short(36);
    try extensions.short(29);
    try extensions.vector16(&@as([32]u8, @splat(0x42)));
    try extensions.put(extra_extensions);
    var encoder: Encoder = .{ .bytes = out };
    try encoder.handshake(1);
    try encoder.short(0x0303);
    try encoder.put(&@as([32]u8, @splat(0x24)));
    try encoder.vector8(session_id);
    try encoder.vector16("\x13\x01\x13\x03\xc0\x2b\xcc\xa9\xc0\x2f");
    try encoder.vector8("\x00");
    try encoder.vector16(extension_buffer[0..extensions.offset]);
    return encoder.finish();
}

test "server runtime parses bounded hello identity ALPN versions groups and key shares" {
    var storage: [1024]u8 = undefined;
    const message = try helloFixture(&storage, "", "session");
    const hello = try parseHello(message);
    try std.testing.expectEqualStrings("session", hello.session_id);
    try std.testing.expectEqualStrings("localhost", hello.hostname.?);
    try std.testing.expectEqualStrings("http/1.1", hello.protocols.slice()[0]);
    try std.testing.expect(hello.tls13 and hello.tls12 and hello.ems);
    try std.testing.expectEqual(3, hello.groups.len);
    try std.testing.expectEqual(29, hello.shares.slice()[0].group);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0x42)), hello.shares.slice()[0].key);
    for (0..message.len) |length| try std.testing.expectError(error.TlsDecodeError, parseHello(message[0..length]));
    const long_session = try helloFixture(&storage, "", &@as([33]u8, @splat(1)));
    try std.testing.expectError(error.TlsIllegalParameter, parseHello(long_session));
}

test "server runtime rejects duplicate malformed and early-data extensions" {
    var storage: [1024]u8 = undefined;
    try std.testing.expectError(error.TlsIllegalParameter, parseHello(try helloFixture(&storage, "\x00\x17\x00\x00", "")));
    try std.testing.expectError(error.TlsDecodeError, parseHello(try helloFixture(&storage, "\x12\x34\x00\x05\x00", "")));
    try std.testing.expectError(error.TlsDecodeError, parseHello(try helloFixture(&storage, "\x12", "")));
    try std.testing.expectError(error.TlsUnexpectedMessage, parseHello(try helloFixture(&storage, "\x00\x2a\x00\x00", "")));
    const message = try helloFixture(&storage, "", "");
    const alpn_header = std.mem.indexOf(u8, message, "\x00\x10\x00\x0b").?;
    storage[alpn_header + 5] += 1;
    try std.testing.expectError(error.TlsDecodeError, parseHello(message));
}

test "server runtime filters cipher signatures and shares by selected capabilities" {
    var storage: [1024]u8 = undefined;
    var hello = try parseHello(try helloFixture(&storage, "", ""));
    var identity: Identity = undefined;
    identity.key.algorithm = .ecdsa_p256;
    identity.schemes = p.Capabilities.all();
    for (std.enums.values(p.SignatureScheme)) |scheme| identity.schemes.setSign(scheme, scheme.keyAlgorithm() == .ecdsa_p256);
    var caps = p.Capabilities.all();
    try std.testing.expectEqual(tls.CipherSuite.CHACHA20_POLY1305_SHA256, try selectSuite(&hello, caps, &identity, .tls_1_3));
    try std.testing.expectEqual(tls.CipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, try selectSuite(&hello, caps, &identity, .tls_1_2));
    caps.setAead(.chacha20_poly1305, false);
    try std.testing.expectEqual(tls.CipherSuite.AES_128_GCM_SHA256, try selectSuite(&hello, caps, &identity, .tls_1_3));
    caps.setHkdf(.sha256, false);
    try std.testing.expectError(error.TlsUnsupportedCipherSuite, selectSuite(&hello, caps, &identity, .tls_1_3));
    caps.setHmac(.sha256, false);
    try std.testing.expectEqual(tls.CipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, try selectSuite(&hello, caps, &identity, .tls_1_2));
    try std.testing.expectEqual(p.SignatureScheme.ecdsa_secp256r1_sha256, try selectSignature(&hello, &identity, .tls_1_3));
    try std.testing.expectEqual(29, try selectGroup(&hello, caps, .tls_1_3));
    caps.setKeyAgreement(.x25519, false);
    try std.testing.expectError(error.TlsKeyExchangeFailed, selectGroup(&hello, caps, .tls_1_3));
    try std.testing.expectEqual(23, try selectGroup(&hello, caps, .tls_1_2));
    hello.groups.len = 1;
    try std.testing.expectError(error.UnsupportedAlgorithm, selectSignature(&hello, &identity, .tls_1_2));
    hello.suites.len = 0;
    try std.testing.expectError(error.TlsUnsupportedCipherSuite, selectSuite(&hello, caps, &identity, .tls_1_2));
}

test "server runtime hello framing echoes TLS13 sessions and encodes TLS12 ALPN and EMS" {
    var input: [1024]u8 = undefined;
    const hello = try parseHello(try helloFixture(&input, "", "session"));
    var output: [2048]u8 = undefined;
    const random: [32]u8 = @splat(0x12);
    const public: [32]u8 = @splat(0x42);
    const tls13 = try serverHello(&output, &hello, .tls_1_3, .AES_128_GCM_SHA256, &random, 29, &public, null);
    var decoder: Decoder = .{ .bytes = tls13[4..] };
    try std.testing.expectEqual(0x0303, try decoder.short());
    try std.testing.expectEqualSlices(u8, &random, try decoder.take(32));
    try std.testing.expectEqualStrings("session", try decoder.vector8());
    const tls12 = try serverHello(&output, &hello, .tls_1_2, .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &random, 29, "", "http/1.1");
    decoder = .{ .bytes = tls12[4..] };
    _ = try decoder.take(34);
    try std.testing.expectEqual(0, (try decoder.vector8()).len);
    _ = try decoder.take(3);
    const extensions = try decoder.vector16();
    try decoder.finish();
    try std.testing.expect(std.mem.indexOf(u8, extensions, "\x00\x17\x00\x00") != null);
    try std.testing.expect(std.mem.indexOf(u8, extensions, "\x00\x10\x00\x0b\x00\x09\x08http/1.1") != null);
    try std.testing.expectError(error.TlsRecordOverflow, serverHello(output[0..10], &hello, .tls_1_3, .AES_128_GCM_SHA256, &random, 29, &public, null));
}

const MemoryTransport = struct {
    incoming: []const u8 = "",
    offset: usize = 0,
    outgoing: std.ArrayList(u8) = .empty,
    chunk: usize = 3,

    fn recv(self: *MemoryTransport, out: []u8) !usize {
        const length = @min(out.len, self.chunk, self.incoming.len - self.offset);
        @memcpy(out[0..length], self.incoming[self.offset..][0..length]);
        self.offset += length;
        return length;
    }

    fn sendAll(self: *MemoryTransport, bytes: []const u8) !void {
        try self.outgoing.appendSlice(std.testing.allocator, bytes);
    }

    fn recvWithContext(self: *MemoryTransport, out: []u8, context: *const IoContext) !usize {
        try context.check();
        return self.recv(out);
    }

    fn sendAllWithContext(self: *MemoryTransport, bytes: []const u8, context: *const IoContext) !void {
        try context.check();
        return self.sendAll(bytes);
    }

    fn deinit(self: *MemoryTransport) void {
        self.outgoing.deinit(std.testing.allocator);
    }
};

test "server runtime reassembles fragmented and coalesced handshakes without crossing epochs" {
    var standard = engine.StandardCryptoProvider.init(std.testing.io, std.testing.allocator);
    var transport: MemoryTransport = .{};
    defer transport.deinit();
    var sender: Wire(MemoryTransport) = .{ .socket = &transport, .provider = standard.provider() };
    try sender.sendRecord(22, "\x0e\x00");
    try sender.sendRecord(22, "\x00\x00\x0e\x00\x00\x00");
    transport.incoming = transport.outgoing.items;
    var receiver: Wire(MemoryTransport) = .{ .socket = &transport, .provider = standard.provider() };
    try std.testing.expectEqualStrings("\x0e\x00\x00\x00", try receiver.next(14));
    try std.testing.expectError(error.TlsUnexpectedMessage, receiver.enableRead(.{}));
    try std.testing.expectEqualStrings("\x0e\x00\x00\x00", try receiver.next(14));
    try receiver.enableRead(.{});
    try std.testing.expectEqual(0, receiver.start);
    try std.testing.expectEqual(0, receiver.end);
}

test "server runtime fragments complete large certificate messages without truncation" {
    const certificate: [20000]u8 = @splat(0x42);
    const message = try certificateMessage(std.testing.allocator, &.{&certificate}, .tls_1_3);
    defer std.testing.allocator.free(message);
    try std.testing.expectEqual(message.len - 4, std.mem.readInt(u24, message[1..4], .big));
    var standard = engine.StandardCryptoProvider.init(std.testing.io, std.testing.allocator);
    var transcript = try state.HashType(.sha256).init(standard.provider(), std.testing.allocator);
    defer transcript.deinit();
    var transport: MemoryTransport = .{};
    defer transport.deinit();
    var sender: Wire(MemoryTransport) = .{
        .socket = &transport,
        .provider = standard.provider(),
        .version = .tls_1_3,
        .write_epoch = .{ .keys = .{} },
    };
    try sender.send(&transcript, message);
    try std.testing.expectEqual(2, sender.write_epoch.?.sequence);
    transport.incoming = transport.outgoing.items;
    var receiver: Wire(MemoryTransport) = .{
        .socket = &transport,
        .provider = standard.provider(),
        .version = .tls_1_3,
        .read_epoch = .{ .keys = .{} },
    };
    var offset: usize = 0;
    for (0..2) |_| {
        const incoming = try receiver.receiveRecord(null);
        try std.testing.expectEqual(22, incoming.kind);
        try std.testing.expect(incoming.bytes.len <= max_plaintext);
        try std.testing.expectEqualSlices(u8, message[offset..][0..incoming.bytes.len], incoming.bytes);
        offset += incoming.bytes.len;
    }
    try std.testing.expectEqual(message.len, offset);
}

test "server runtime never substitutes a rejected record provider" {
    const Failure = struct {
        fn seal(_: *anyopaque, _: p.AeadAlgorithm, _: []const u8, _: []const u8, _: []const []const u8, _: []const u8, _: []u8, _: []u8) p.ProviderError!void {
            return error.UnsupportedAlgorithm;
        }
        fn open(_: *anyopaque, _: p.AeadAlgorithm, _: []const u8, _: []const u8, _: []const []const u8, _: []const u8, _: []const u8, _: []u8) p.ProviderError!void {
            return error.AuthenticationFailed;
        }
    };
    var standard = engine.StandardCryptoProvider.init(std.testing.io, std.testing.allocator);
    var table = standard.provider().vtable.*;
    table.aeadSeal = Failure.seal;
    table.aeadOpen = Failure.open;
    var transport: MemoryTransport = .{};
    defer transport.deinit();
    var wire: Wire(MemoryTransport) = .{
        .socket = &transport,
        .provider = p.CryptoProvider.init(&standard, &table),
        .version = .tls_1_3,
        .write_epoch = .{ .keys = .{} },
        .read_epoch = .{ .keys = .{} },
    };
    try std.testing.expectError(error.UnsupportedAlgorithm, wire.sendRecord(22, "\x0e\x00\x00\x00"));
    try std.testing.expectEqual(0, transport.outgoing.items.len);
    try std.testing.expectEqual(0, wire.write_epoch.?.sequence);
    const invalid = "\x17\x03\x03\x00\x11".* ++ @as([17]u8, @splat(0));
    transport.incoming = &invalid;
    try std.testing.expectError(error.TlsDecryptError, wire.receiveRecord(null));
    try std.testing.expectEqual(0, wire.read_epoch.?.sequence);
}

test "server runtime advances encrypted record sequence before partial transport failure" {
    const PartialTransport = struct {
        written: usize = 0,
        failure: anyerror,

        fn sendAll(self: *@This(), bytes: []const u8) !void {
            self.written += @min(bytes.len, 7);
            return self.failure;
        }

        fn sendAllWithContext(self: *@This(), bytes: []const u8, context: *const IoContext) !void {
            try context.check();
            return self.sendAll(bytes);
        }
    };
    var standard = engine.StandardCryptoProvider.init(std.testing.io, std.testing.allocator);
    for ([_]tls.ProtocolVersion{ .tls_1_2, .tls_1_3 }) |version| {
        for ([_]anyerror{ error.WriteFailed, error.Cancelled, error.Timeout }) |failure| {
            for ([_]bool{ false, true }) |with_context| {
                const context = IoContext.init(.{});
                var transport = PartialTransport{ .failure = failure };
                var wire: Wire(PartialTransport) = .{
                    .socket = &transport,
                    .provider = standard.provider(),
                    .version = version,
                    .suite = if (version == .tls_1_3) .AES_128_GCM_SHA256 else .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    .write_epoch = .{ .keys = .{} },
                    .io_options = if (with_context) .{ .context = &context } else null,
                };
                try std.testing.expectError(failure, wire.sendRecord(22, "\x0e\x00\x00\x00"));
                try std.testing.expectEqual(@as(usize, 7), transport.written);
                try std.testing.expectEqual(@as(u64, 1), wire.write_epoch.?.sequence);
            }
        }
    }
}

test "TLS server context preserves fatal alerts malformed records and unauthenticated EOF errors" {
    var standard = engine.StandardCryptoProvider.init(std.testing.io, std.testing.allocator);
    const context = IoContext.init(.{});
    const cases = .{
        .{ "\x15\x03\x03\x00\x02\x02\x50", error.TlsAlert },
        .{ "\x16\x03\x00\x00\x00", error.TlsIllegalParameter },
        .{ "\x16\x03", error.UnexpectedEof },
    };
    inline for (cases) |case| {
        var transport = MemoryTransport{ .incoming = case[0] };
        defer transport.deinit();
        var wire: Wire(MemoryTransport) = .{
            .socket = &transport,
            .provider = standard.provider(),
            .io_options = .{ .context = &context },
        };
        try std.testing.expectError(case[1], wire.next(1));
    }
    const invalid = "\x17\x03\x03\x00\x11".* ++ @as([17]u8, @splat(0));
    var transport = MemoryTransport{ .incoming = &invalid };
    defer transport.deinit();
    var wire: Wire(MemoryTransport) = .{
        .socket = &transport,
        .provider = standard.provider(),
        .version = .tls_1_3,
        .read_epoch = .{ .keys = .{} },
        .io_options = .{ .context = &context },
    };
    try std.testing.expectError(error.TlsDecryptError, wire.next(1));
    try std.testing.expectEqual(@as(u64, 0), wire.read_epoch.?.sequence);
    try std.testing.expect(std.mem.allEqual(u8, wire.record_buffer[0..1], 0));
}

const DeadlineTransport = struct {
    memory: MemoryTransport = .{ .chunk = 1 },
    deadline: ?io_context.Deadline = null,
    read_calls: usize = 0,
    write_calls: usize = 0,

    fn observe(self: *@This(), context: *const IoContext) !void {
        const deadline = context.selectedDeadline().?.deadline;
        if (self.deadline) |original| {
            try std.testing.expectEqual(original.at_ns, deadline.at_ns);
        } else self.deadline = deadline;
    }

    fn recv(self: *@This(), out: []u8) !usize {
        return self.memory.recv(out);
    }

    fn recvWithContext(self: *@This(), out: []u8, context: *const IoContext) !usize {
        self.read_calls += 1;
        try self.observe(context);
        if (self.memory.offset == 9) {
            // Advance the observation time, not the context's actual deadline.
            try context.checkAt(self.deadline.?.at_ns);
            return error.FixtureDeadlineWasReset;
        }
        return self.recv(out);
    }

    fn sendAll(self: *@This(), bytes: []const u8) !void {
        return self.memory.sendAll(bytes);
    }

    fn sendAllWithContext(self: *@This(), bytes: []const u8, context: *const IoContext) !void {
        self.write_calls += 1;
        try self.observe(context);
        if (self.write_calls == 2) {
            try self.memory.sendAll(bytes[0..@min(bytes.len, 7)]);
            try context.checkAt(self.deadline.?.at_ns);
            return error.FixtureDeadlineWasReset;
        }
        return self.sendAll(bytes);
    }
};

test "TLS server context read deadline spans partial headers bodies and handshake records" {
    var standard = engine.StandardCryptoProvider.init(std.testing.io, std.testing.allocator);
    var transport = DeadlineTransport{};
    defer transport.memory.deinit();
    var writer: Wire(DeadlineTransport) = .{ .socket = &transport, .provider = standard.provider() };
    try writer.sendRecord(22, "\x0e\x00");
    try writer.sendRecord(22, "\x00\x00");
    transport.memory.incoming = transport.memory.outgoing.items;
    var parent = IoContext.init(.{ .request_deadline = io_context.Deadline.afterMs(10_000), .phase_deadline = io_context.Deadline.afterMs(5_000) });
    const original_request = parent.request_deadline;
    const original_phase = parent.phase_deadline;
    var reader: Wire(DeadlineTransport) = .{
        .socket = &transport,
        .provider = standard.provider(),
        .io_options = .{ .context = &parent, .read_timeout_ms = 2_000 },
    };
    try std.testing.expectError(error.Timeout, reader.next(14));
    try std.testing.expectEqual(@as(usize, 9), transport.memory.offset);
    try std.testing.expectEqual(@as(usize, 10), transport.read_calls);
    try std.testing.expect(transport.deadline.?.at_ns < original_phase.?.at_ns);
    try std.testing.expectEqual(original_request, parent.request_deadline);
    try std.testing.expectEqual(original_phase, parent.phase_deadline);
}

test "TLS server context write deadline spans record fragments and retains consumed nonces" {
    const Transcript = struct {
        fn update(_: *@This(), _: []const u8) !void {}
    };
    var transcript = Transcript{};
    var standard = engine.StandardCryptoProvider.init(std.testing.io, std.testing.allocator);
    var transport = DeadlineTransport{};
    defer transport.memory.deinit();
    var parent = IoContext.init(.{ .request_deadline = io_context.Deadline.afterMs(10_000) });
    const original = parent.request_deadline;
    var writer: Wire(DeadlineTransport) = .{
        .socket = &transport,
        .provider = standard.provider(),
        .version = .tls_1_3,
        .write_epoch = .{ .keys = .{} },
        .io_options = .{ .context = &parent, .write_timeout_ms = 2_000 },
    };
    const message: [max_plaintext + 1]u8 = @splat(0x42);
    try std.testing.expectError(error.Timeout, writer.send(&transcript, &message));
    try std.testing.expectEqual(@as(usize, 2), transport.write_calls);
    try std.testing.expectEqual(@as(usize, max_plaintext + 1 + 16 + 5 + 7), transport.memory.outgoing.items.len);
    try std.testing.expectEqual(@as(u64, 2), writer.write_epoch.?.sequence);
    try std.testing.expectEqual(original, parent.request_deadline);
}

test "TLS server context zero budgets and earliest inherited deadlines precede transport" {
    var standard = engine.StandardCryptoProvider.init(std.testing.io, std.testing.allocator);
    var transport = DeadlineTransport{};
    defer transport.memory.deinit();
    var token: @import("../core/types.zig").CancellationToken = .{};
    var parent = IoContext.init(.{ .external_cancel = &token });
    var wire: Wire(DeadlineTransport) = .{
        .socket = &transport,
        .provider = standard.provider(),
        .io_options = .{ .context = &parent, .read_timeout_ms = 0, .write_timeout_ms = 0 },
    };
    try std.testing.expectError(error.Timeout, wire.next(1));
    try std.testing.expectError(error.Timeout, wire.sendRecord(20, "\x01"));
    wire.io_options.?.read_timeout_ms = 2_000;
    wire.io_options.?.write_timeout_ms = 2_000;
    parent.request_deadline = io_context.Deadline.at(0);
    try std.testing.expectError(error.Timeout, wire.next(1));
    try std.testing.expectError(error.Timeout, wire.sendRecord(20, "\x01"));
    token.cancel();
    try std.testing.expectError(error.Cancelled, wire.next(1));
    try std.testing.expectError(error.Cancelled, wire.sendRecord(20, "\x01"));
    try std.testing.expectEqual(@as(usize, 0), transport.read_calls);
    try std.testing.expectEqual(@as(usize, 0), transport.write_calls);
}

test "TLS server context checks win over read and partial write failures after blocking" {
    const Boundary = struct {
        parent: *IoContext,
        cancel: bool,
        calls: usize = 0,
        written: usize = 0,

        fn boundary(self: *@This(), context: *const IoContext) !void {
            self.calls += 1;
            context.waitForMs(2_000) catch |err| {
                if (err != error.Timeout) return err;
                if (self.cancel) self.parent.cancel();
                return;
            };
            return error.FixtureDeadlineMissing;
        }
        fn recv(_: *@This(), _: []u8) !usize {
            return error.ReadFailed;
        }
        fn recvWithContext(self: *@This(), _: []u8, context: *const IoContext) !usize {
            try self.boundary(context);
            return error.ReadFailed;
        }
        fn sendAll(_: *@This(), _: []const u8) !void {
            return error.WriteFailed;
        }
        fn sendAllWithContext(self: *@This(), bytes: []const u8, context: *const IoContext) !void {
            self.written += @min(bytes.len, 7);
            try self.boundary(context);
            return error.WriteFailed;
        }
    };
    var standard = engine.StandardCryptoProvider.init(std.testing.io, std.testing.allocator);
    for ([_]bool{ false, true }) |cancel| {
        for ([_]bool{ false, true }) |write| {
            var parent = IoContext.init(.{});
            var transport = Boundary{ .parent = &parent, .cancel = cancel };
            var wire: Wire(Boundary) = .{
                .socket = &transport,
                .provider = standard.provider(),
                .version = .tls_1_3,
                .write_epoch = .{ .keys = .{} },
                .io_options = .{ .context = &parent, .read_timeout_ms = 20, .write_timeout_ms = 20 },
            };
            const expected = if (cancel) error.Cancelled else error.Timeout;
            if (write) {
                try std.testing.expectError(expected, wire.sendRecord(22, "\x0e\x00\x00\x00"));
                try std.testing.expectEqual(@as(u64, 1), wire.write_epoch.?.sequence);
                try std.testing.expectEqual(@as(usize, 7), transport.written);
            } else try std.testing.expectError(expected, wire.next(1));
            try std.testing.expectEqual(@as(usize, 1), transport.calls);
            try std.testing.expectEqual(@as(?io_context.Deadline, null), parent.phase_deadline);
        }
    }
}
