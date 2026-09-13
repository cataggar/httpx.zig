//! Two-prime RSA private operations using std.crypto.ff. Key validation is a
//! setup operation; signing uses fixed-width secret exponents, fresh message
//! blinding, and public-exponent verification before releasing any signature.
const std = @import("std");
const p = @import("provider.zig");
const der = @import("der.zig");
const algorithms = @import("algorithm_encoding.zig");
const Error = p.ProviderError;
const Modulus = std.crypto.ff.Modulus(4096);
const Uint = std.crypto.ff.Uint(4096);

const Components = struct {
    n: []const u8,
    e: []const u8,
    d: []const u8,
    prime_p: []const u8,
    prime_q: []const u8,
    dp: []const u8,
    dq: []const u8,
    qi: []const u8,
    restrictions: ?algorithms.PssParameters = null,
};

pub const Key = struct {
    modulus: Modulus,
    exponent: [4]u8 = @splat(0),
    exponent_length: usize,
    private_exponent: [512]u8 = @splat(0),
    inverse_exponent: [512]u8 = @splat(0),
    length: usize,
    algorithm: p.SignatureKeyAlgorithm,
    restrictions: ?algorithms.PssParameters,

    pub fn init(io: std.Io, input: p.PrivateKey) Error!Key {
        const fields = try decode(input);
        if ((fields.n.len != 256 and fields.n.len != 384 and fields.n.len != 512) or
            fields.n[0] & 0x80 == 0) return error.UnsupportedAlgorithm;
        if (fields.e.len > 4) return error.UnsupportedAlgorithm;
        const e = std.mem.readVarInt(u32, fields.e, .big);
        if (e < 3 or e & 1 == 0) return error.InvalidEncoding;
        const prime_length = fields.n.len / 2;
        if (fields.prime_p.len != prime_length or fields.prime_q.len != prime_length or
            fields.prime_p[0] & 0x80 == 0 or fields.prime_q[0] & 0x80 == 0)
            return error.UnsupportedAlgorithm;
        if (fields.d.len > fields.n.len or fields.dp.len > prime_length or
            fields.dq.len > prime_length or fields.qi.len > prime_length) return error.InvalidEncoding;

        // Wide integer arithmetic is confined to key setup, never a signing
        // operation. Validate every supplied CRT component even though signing
        // deliberately uses the full modulus rather than CRT recombination.
        var values = .{
            .n = std.mem.readVarInt(u4096, fields.n, .big),
            .d = std.mem.readVarInt(u4096, fields.d, .big),
            .prime_p = std.mem.readVarInt(u4096, fields.prime_p, .big),
            .prime_q = std.mem.readVarInt(u4096, fields.prime_q, .big),
            .dp = std.mem.readVarInt(u4096, fields.dp, .big),
            .dq = std.mem.readVarInt(u4096, fields.dq, .big),
            .qi = std.mem.readVarInt(u4096, fields.qi, .big),
        };
        defer p.secureWipeValue(&values);
        if (values.prime_p & 1 == 0 or values.prime_q & 1 == 0 or
            values.prime_p == values.prime_q or values.d >= values.n or values.qi >= values.prime_p)
            return error.InvalidEncoding;
        if (values.prime_p * values.prime_q != values.n) return error.InvalidEncoding;
        var p_minus_one = values.prime_p - 1;
        defer p.secureWipeValue(&p_minus_one);
        var q_minus_one = values.prime_q - 1;
        defer p.secureWipeValue(&q_minus_one);
        if (values.dp != values.d % p_minus_one or values.dq != values.d % q_minus_one or
            values.qi * values.prime_q % values.prime_p != 1) return error.InvalidEncoding;
        var lambda = (p_minus_one / std.math.gcd(p_minus_one, q_minus_one)) * q_minus_one;
        defer p.secureWipeValue(&lambda);
        var de = @as(u8192, values.d) * e;
        defer p.secureWipeValue(&de);
        if (de % lambda != 1) return error.InvalidEncoding;
        if (fields.restrictions) |restriction| {
            if (restriction.hash == .sha1 or restriction.mgf_hash != restriction.hash or
                restriction.trailer != 1 or restriction.salt_length > restriction.hash.digestLength())
                return error.UnsupportedAlgorithm;
        }
        if (!try isProbablePrime(io, fields.prime_p) or !try isProbablePrime(io, fields.prime_q))
            return error.InvalidEncoding;

        var result: Key = .{
            .modulus = Modulus.fromBytes(fields.n, .big) catch return error.InvalidEncoding,
            .exponent_length = fields.e.len,
            .length = fields.n.len,
            .algorithm = input.algorithm,
            .restrictions = fields.restrictions,
        };
        errdefer p.secureWipeValue(&result);
        @memcpy(result.exponent[0..fields.e.len], fields.e);
        @memcpy(result.private_exponent[fields.n.len - fields.d.len .. fields.n.len], fields.d);
        // Euler's theorem provides the inverse of an independently sampled
        // invertible blinding factor without a variable-time secret inversion.
        writeInteger(result.inverse_exponent[0..result.length], values.n - values.prime_p - values.prime_q);
        return result;
    }

    pub fn sign(self: *const Key, io: std.Io, scheme: p.SignatureScheme, parts: []const []const u8, out: []u8) Error!usize {
        if (scheme.signatureEncoding() != .rsa_raw or scheme.keyAlgorithm() != self.algorithm or
            scheme == .rsa_pkcs1_sha1) return error.UnsupportedAlgorithm;
        const hash = scheme.hashAlgorithm().?;
        if (self.restrictions) |restriction| {
            if (restriction.hash != hash or restriction.mgf_hash != hash or
                restriction.salt_length > hash.digestLength() or restriction.trailer != 1)
                return error.UnsupportedAlgorithm;
        }
        if (out.len < self.length) return error.OutputTooSmall;
        var encoded: [512]u8 = undefined;
        defer p.secureWipe(&encoded);
        const pkcs1 = switch (scheme) {
            .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 => true,
            else => false,
        };
        switch (hash) {
            inline .sha256, .sha384, .sha512 => |algorithm| try encode(algorithm, io, pkcs1, parts, encoded[0..self.length]),
            .sha1 => return error.UnsupportedAlgorithm,
        }
        try self.privateOperation(io, encoded[0..self.length], out[0..self.length]);
        return self.length;
    }

    fn privateOperation(self: *const Key, io: std.Io, encoded: []const u8, out: []u8) Error!void {
        const modulus = self.modulus;
        var message = Modulus.Fe.fromBytes(modulus, encoded, .big) catch return error.SigningFailed;
        defer p.secureWipeValue(&message);
        var random_bytes: [512]u8 = undefined;
        defer p.secureWipe(&random_bytes);
        for (0..64) |_| {
            try random(io, random_bytes[0..self.length]);
            var factor = Modulus.Fe.fromBytes(modulus, random_bytes[0..self.length], .big) catch continue;
            defer p.secureWipeValue(&factor);
            if (factor.isZero() or factor.eql(modulus.one())) continue;
            var inverse = modulus.powWithEncodedExponent(factor, self.inverse_exponent[0..self.length], .big) catch return error.SigningFailed;
            defer p.secureWipeValue(&inverse);
            var identity = modulus.mul(factor, inverse);
            defer p.secureWipeValue(&identity);
            if (!identity.eql(modulus.one())) continue;
            var public_factor = modulus.powWithEncodedPublicExponent(factor, self.exponent[0..self.exponent_length], .big) catch return error.SigningFailed;
            defer p.secureWipeValue(&public_factor);
            var blinded = modulus.mul(message, public_factor);
            defer p.secureWipeValue(&blinded);
            var blinded_signature = modulus.powWithEncodedExponent(blinded, self.private_exponent[0..self.length], .big) catch return error.SigningFailed;
            defer p.secureWipeValue(&blinded_signature);
            var signature = modulus.mul(blinded_signature, inverse);
            defer p.secureWipeValue(&signature);
            var check = modulus.powWithEncodedPublicExponent(signature, self.exponent[0..self.exponent_length], .big) catch return error.SigningFailed;
            defer p.secureWipeValue(&check);
            if (!check.eql(message)) return error.SigningFailed;
            signature.toBytes(out, .big) catch return error.SigningFailed;
            return;
        }
        return error.EntropyUnavailable;
    }
};

fn random(io: std.Io, out: []u8) Error!void {
    io.randomSecure(out) catch return error.EntropyUnavailable;
}

fn writeInteger(out: []u8, value: u4096) void {
    var bytes: [512]u8 = undefined;
    defer p.secureWipe(&bytes);
    std.mem.writeInt(u4096, &bytes, value, .big);
    @memcpy(out, bytes[bytes.len - out.len ..]);
}

fn isProbablePrime(io: std.Io, bytes: []const u8) Error!bool {
    var value = std.mem.readVarInt(u4096, bytes, .big);
    defer p.secureWipeValue(&value);
    for ([_]u16{ 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97 }) |prime| {
        if (value % prime == 0) return false;
    }
    var modulus = Modulus.fromBytes(bytes, .big) catch return false;
    defer p.secureWipeValue(&modulus);
    const twos: usize = @intCast(@ctz(value - 1));
    var exponent: [256]u8 = undefined;
    defer p.secureWipe(&exponent);
    writeInteger(exponent[0..bytes.len], (value - 1) >> @intCast(twos));
    var minus_one = modulus.sub(modulus.zero, modulus.one());
    defer p.secureWipeValue(&minus_one);
    var random_bytes: [512]u8 = undefined;
    defer p.secureWipe(&random_bytes);
    var rounds: usize = 0;
    // 65 random Miller–Rabin witnesses bound error below 2^-128, including
    // double-width sampling's negligible bias for the supported prime sizes.
    for (0..128) |_| {
        try random(io, random_bytes[0 .. bytes.len * 2]);
        var wide = Uint.fromBytes(random_bytes[0 .. bytes.len * 2], .big) catch return error.InvalidEncoding;
        defer p.secureWipeValue(&wide);
        var base = modulus.reduce(wide);
        defer p.secureWipeValue(&base);
        if (base.isZero() or base.eql(modulus.one()) or base.eql(minus_one)) continue;
        var witness = modulus.powWithEncodedExponent(base, exponent[0..bytes.len], .big) catch return error.InvalidEncoding;
        defer p.secureWipeValue(&witness);
        var probable = witness.eql(modulus.one()) or witness.eql(minus_one);
        if (!probable) {
            for (1..twos) |_| {
                witness = modulus.sq(witness);
                if (witness.eql(minus_one)) {
                    probable = true;
                    break;
                }
                if (witness.eql(modulus.one())) break;
            }
        }
        if (!probable) return false;
        rounds += 1;
        if (rounds == 65) return true;
    }
    return error.EntropyUnavailable;
}

fn decode(input: p.PrivateKey) Error!Components {
    if (input.algorithm != .rsa and input.algorithm != .rsa_pss) return error.UnsupportedAlgorithm;
    if (input.bytes.len > 16 * 1024) return error.InvalidEncoding;
    switch (input.encoding) {
        .rsa_pkcs1_der => return decodePkcs1(input.bytes),
        .pkcs8_der => {
            var container = try der.sequence(input.bytes);
            const version = try container.take(0x02);
            if (version.len != 1 or version[0] > 1) return error.InvalidEncoding;
            var identifier: der.Reader = .{ .bytes = try container.take(0x30) };
            const oid = try identifier.take(0x06);
            const expected = if (input.algorithm == .rsa) algorithms.rsa_oid else algorithms.pss_oid;
            if (!std.mem.eql(u8, oid, expected)) return error.InvalidEncoding;
            var restrictions: ?algorithms.PssParameters = null;
            if (identifier.offset < identifier.bytes.len) {
                if (input.algorithm == .rsa) {
                    if ((try identifier.take(0x05)).len != 0) return error.InvalidEncoding;
                } else {
                    const parameters = try identifier.element();
                    restrictions = try algorithms.parsePss(parameters.encoded);
                }
            }
            try identifier.finish();
            var fields = try decodePkcs1(try container.take(0x04));
            fields.restrictions = restrictions;
            if (container.offset < container.bytes.len and container.bytes[container.offset] == 0xa0)
                return error.UnsupportedOperation;
            if (version[0] == 1) {
                const public_key = try container.take(0x81);
                if (public_key.len < 2 or public_key[0] != 0) return error.InvalidEncoding;
                var public = try der.sequence(public_key[1..]);
                if (!std.mem.eql(u8, try der.positiveInteger(&public), fields.n) or
                    !std.mem.eql(u8, try der.positiveInteger(&public), fields.e)) return error.InvalidEncoding;
                try public.finish();
            }
            try container.finish();
            return fields;
        },
        else => return error.UnsupportedAlgorithm,
    }
}

fn decodePkcs1(bytes: []const u8) Error!Components {
    var sequence = try der.sequence(bytes);
    const version = try sequence.take(0x02);
    if (version.len == 1 and version[0] == 1) return error.UnsupportedAlgorithm;
    if (!std.mem.eql(u8, version, "\x00")) return error.InvalidEncoding;
    const result: Components = .{
        .n = try der.positiveInteger(&sequence),
        .e = try der.positiveInteger(&sequence),
        .d = try der.positiveInteger(&sequence),
        .prime_p = try der.positiveInteger(&sequence),
        .prime_q = try der.positiveInteger(&sequence),
        .dp = try der.positiveInteger(&sequence),
        .dq = try der.positiveInteger(&sequence),
        .qi = try der.positiveInteger(&sequence),
    };
    try sequence.finish();
    return result;
}

fn Hash(comptime algorithm: p.HashAlgorithm) type {
    return switch (algorithm) {
        .sha256 => std.crypto.hash.sha2.Sha256,
        .sha384 => std.crypto.hash.sha2.Sha384,
        .sha512 => std.crypto.hash.sha2.Sha512,
        .sha1 => unreachable,
    };
}

fn encode(comptime algorithm: p.HashAlgorithm, io: std.Io, pkcs1: bool, parts: []const []const u8, out: []u8) Error!void {
    const Hasher = Hash(algorithm);
    const digest_length = Hasher.digest_length;
    var hasher = Hasher.init(.{});
    defer p.secureWipeValue(&hasher);
    for (parts) |part| hasher.update(part);
    var message_hash: [digest_length]u8 = undefined;
    defer p.secureWipe(&message_hash);
    hasher.final(&message_hash);
    if (pkcs1) {
        const prefix = switch (algorithm) {
            .sha256 => "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
            .sha384 => "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
            .sha512 => "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
            .sha1 => unreachable,
        };
        const separator = out.len - prefix.len - digest_length - 1;
        out[0] = 0;
        out[1] = 1;
        @memset(out[2..separator], 0xff);
        out[separator] = 0;
        @memcpy(out[separator + 1 ..][0..prefix.len], prefix);
        @memcpy(out[out.len - digest_length ..], &message_hash);
        return;
    }
    var salt: [digest_length]u8 = undefined;
    defer p.secureWipe(&salt);
    try random(io, &salt);
    hasher = Hasher.init(.{});
    hasher.update(&@as([8]u8, @splat(0)));
    hasher.update(&message_hash);
    hasher.update(&salt);
    var h: [digest_length]u8 = undefined;
    defer p.secureWipe(&h);
    hasher.final(&h);
    const db_length = out.len - digest_length - 1;
    @memset(out[0 .. db_length - digest_length - 1], 0);
    out[db_length - digest_length - 1] = 1;
    @memcpy(out[db_length - digest_length .. db_length], &salt);
    var counter: u32 = 0;
    var offset: usize = 0;
    while (offset < db_length) : (counter += 1) {
        var counter_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &counter_bytes, counter, .big);
        hasher = Hasher.init(.{});
        hasher.update(&h);
        hasher.update(&counter_bytes);
        var mask: [digest_length]u8 = undefined;
        defer p.secureWipe(&mask);
        hasher.final(&mask);
        const length = @min(digest_length, db_length - offset);
        for (out[offset..][0..length], mask[0..length]) |*byte, masked| byte.* ^= masked;
        offset += length;
    }
    out[0] &= 0x7f;
    @memcpy(out[db_length..][0..digest_length], &h);
    out[out.len - 1] = 0xbc;
}

test "RSA primality screen rejects composites beyond trial division" {
    var composite: [8]u8 = undefined;
    std.mem.writeInt(u64, &composite, 3215031751, .big);
    try std.testing.expect(!try isProbablePrime(std.testing.io, &composite));
    var prime: [4]u8 = undefined;
    std.mem.writeInt(u32, &prime, 2147483647, .big);
    try std.testing.expect(try isProbablePrime(std.testing.io, &prime));
}
