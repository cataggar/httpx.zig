//! Bounded decoding of unencrypted signature-key containers. Cryptographic
//! validation and ownership of the decoded material belong to the provider.
const std = @import("std");
const p = @import("provider.zig");
const der = @import("der.zig");

pub const Material = struct {
    secret: []const u8,
    public_key: ?[]const u8 = null,
};

const ec_oid = "\x2a\x86\x48\xce\x3d\x02\x01";
const ed25519_oid = "\x2b\x65\x70";

fn curveOid(algorithm: p.SignatureKeyAlgorithm) p.ProviderError![]const u8 {
    return switch (algorithm) {
        .ecdsa_p256 => "\x2a\x86\x48\xce\x3d\x03\x01\x07",
        .ecdsa_p384 => "\x2b\x81\x04\x00\x22",
        else => error.UnsupportedAlgorithm,
    };
}

fn secretLength(algorithm: p.SignatureKeyAlgorithm) p.ProviderError!usize {
    return switch (algorithm) {
        .ecdsa_p256, .ed25519 => 32,
        .ecdsa_p384 => 48,
        else => error.UnsupportedAlgorithm,
    };
}

fn bitString(bytes: []const u8) p.ProviderError![]const u8 {
    if (bytes.len < 2 or bytes[0] != 0) return error.InvalidEncoding;
    return bytes[1..];
}

fn nextTag(reader: der.Reader) ?u8 {
    if (reader.offset == reader.bytes.len) return null;
    return reader.bytes[reader.offset];
}

fn decodeSec1(algorithm: p.SignatureKeyAlgorithm, bytes: []const u8) p.ProviderError!Material {
    const expected_oid = try curveOid(algorithm);
    var reader = try der.sequence(bytes);
    if (!std.mem.eql(u8, try reader.take(0x02), "\x01")) return error.InvalidEncoding;
    const secret = try reader.take(0x04);
    if (secret.len != try secretLength(algorithm)) return error.InvalidKeyLength;
    if (nextTag(reader) == 0xa0) {
        var parameters: der.Reader = .{ .bytes = try reader.take(0xa0) };
        if (!std.mem.eql(u8, try parameters.take(0x06), expected_oid)) return error.InvalidEncoding;
        try parameters.finish();
    }
    var public_key: ?[]const u8 = null;
    if (nextTag(reader) == 0xa1) {
        var public: der.Reader = .{ .bytes = try reader.take(0xa1) };
        public_key = try bitString(try public.take(0x03));
        try public.finish();
    }
    try reader.finish();
    return .{ .secret = secret, .public_key = public_key };
}

fn decodePkcs8(algorithm: p.SignatureKeyAlgorithm, bytes: []const u8) p.ProviderError!Material {
    var reader = try der.sequence(bytes);
    const version = try reader.take(0x02);
    if (version.len != 1 or version[0] > 1) return error.InvalidEncoding;
    var identifier: der.Reader = .{ .bytes = try reader.take(0x30) };
    const oid = try identifier.take(0x06);
    switch (algorithm) {
        .ecdsa_p256, .ecdsa_p384 => {
            if (!std.mem.eql(u8, oid, ec_oid)) return error.InvalidEncoding;
            if (!std.mem.eql(u8, try identifier.take(0x06), try curveOid(algorithm))) return error.InvalidEncoding;
        },
        .ed25519 => if (!std.mem.eql(u8, oid, ed25519_oid)) return error.InvalidEncoding,
        else => return error.UnsupportedAlgorithm,
    }
    try identifier.finish();
    const private = try reader.take(0x04);
    var material: Material = switch (algorithm) {
        .ecdsa_p256, .ecdsa_p384 => try decodeSec1(algorithm, private),
        .ed25519 => blk: {
            var seed: der.Reader = .{ .bytes = private };
            const secret = try seed.take(0x04);
            try seed.finish();
            if (secret.len != 32) return error.InvalidKeyLength;
            break :blk .{ .secret = secret };
        },
        else => unreachable,
    };
    // Attributes are not needed for TLS key use and are not silently ignored.
    if (nextTag(reader) == 0xa0) return error.UnsupportedOperation;
    if (nextTag(reader) == 0x81) {
        if (version[0] != 1) return error.InvalidEncoding;
        const public_key = try bitString(try reader.take(0x81));
        if (material.public_key) |embedded| {
            if (!std.mem.eql(u8, embedded, public_key)) return error.InvalidEncoding;
        }
        material.public_key = public_key;
    } else if (version[0] == 1) return error.InvalidEncoding;
    try reader.finish();
    return material;
}

pub fn decode(input: p.PrivateKey) p.ProviderError!Material {
    if (input.bytes.len > 16 * 1024) return error.InvalidEncoding;
    return switch (input.encoding) {
        .raw_secret => blk: {
            if (input.bytes.len != try secretLength(input.algorithm)) return error.InvalidKeyLength;
            break :blk .{ .secret = input.bytes };
        },
        .sec1_der => decodeSec1(input.algorithm, input.bytes),
        .pkcs8_der => decodePkcs8(input.algorithm, input.bytes),
        .rsa_pkcs1_der => error.UnsupportedAlgorithm,
    };
}
