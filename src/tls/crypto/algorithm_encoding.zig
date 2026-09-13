const std = @import("std");
const der = @import("der.zig");
const p = @import("provider.zig");

pub const Error = der.Error || error{UnsupportedAlgorithm};
pub const rsa_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
pub const pss_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a";

pub const PssParameters = struct {
    hash: p.HashAlgorithm = .sha1,
    mgf_hash: p.HashAlgorithm = .sha1,
    salt_length: usize = 20,
    trailer: usize = 1,
};

pub fn parsePss(bytes: []const u8) Error!PssParameters {
    var reader = try der.sequence(bytes);
    var parameters: PssParameters = .{};
    var previous: u8 = 0;
    while (reader.offset < reader.bytes.len) {
        const field = try reader.element();
        if (field.tag < 0xa0 or field.tag > 0xa3 or field.tag < previous) return error.InvalidEncoding;
        previous = field.tag + 1;
        switch (field.tag) {
            0xa0 => parameters.hash = try parseHash(field.content),
            0xa1 => {
                var mgf = try der.sequence(field.content);
                if (!std.mem.eql(u8, try mgf.take(0x06), "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08"))
                    return error.UnsupportedAlgorithm;
                const hash = try mgf.element();
                parameters.mgf_hash = try parseHash(hash.encoded);
                try mgf.finish();
            },
            0xa2, 0xa3 => {
                var integer: der.Reader = .{ .bytes = field.content };
                const value = try integer.take(0x02);
                try integer.finish();
                if (value.len == 0 or value.len > 2 or value[0] & 0x80 != 0 or
                    (value.len == 2 and value[0] == 0 and value[1] & 0x80 == 0)) return error.InvalidEncoding;
                var result: usize = 0;
                for (value) |byte| result = result * 256 + byte;
                if (field.tag == 0xa2) parameters.salt_length = result else parameters.trailer = result;
            },
            else => unreachable,
        }
    }
    return parameters;
}

fn parseHash(bytes: []const u8) Error!p.HashAlgorithm {
    var algorithm = try der.sequence(bytes);
    const oid = try algorithm.take(0x06);
    if (algorithm.offset < algorithm.bytes.len) {
        if ((try algorithm.take(0x05)).len != 0) return error.InvalidEncoding;
    }
    try algorithm.finish();
    if (std.mem.eql(u8, oid, "\x2b\x0e\x03\x02\x1a")) return .sha1;
    const sha2_prefix = "\x60\x86\x48\x01\x65\x03\x04\x02";
    if (oid.len != sha2_prefix.len + 1 or !std.mem.startsWith(u8, oid, sha2_prefix)) return error.UnsupportedAlgorithm;
    return switch (oid[oid.len - 1]) {
        1 => .sha256,
        2 => .sha384,
        3 => .sha512,
        else => error.UnsupportedAlgorithm,
    };
}
