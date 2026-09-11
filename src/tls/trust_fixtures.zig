//! Deterministic, local test certificates. These public test seeds are not
//! credentials. This module is never imported by the production trust owner.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Scheme = enum { ed25519, ecdsa_p256 };
pub const Key = union(Scheme) {
    ed25519: Ed25519.KeyPair,
    ecdsa_p256: Ecdsa.KeyPair,

    pub fn init(scheme: Scheme, seed: u8) !Key {
        return switch (scheme) {
            .ed25519 => .{ .ed25519 = try Ed25519.KeyPair.generateDeterministic(@splat(seed)) },
            .ecdsa_p256 => .{ .ecdsa_p256 = try Ecdsa.KeyPair.generateDeterministic(@splat(seed)) },
        };
    }

    fn algorithm(self: Key) []const u8 {
        return switch (self) {
            .ed25519 => "\x30\x05\x06\x03\x2b\x65\x70",
            .ecdsa_p256 => "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02",
        };
    }

    fn spki(self: Key, allocator: Allocator) ![]const u8 {
        return switch (self) {
            .ed25519 => |key| join(allocator, &.{
                "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00",
                &key.public_key.toBytes(),
            }),
            .ecdsa_p256 => |key| join(allocator, &.{
                "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00",
                &key.public_key.toUncompressedSec1(),
            }),
        };
    }

    fn sign(self: Key, allocator: Allocator, bytes: []const u8) ![]const u8 {
        return switch (self) {
            .ed25519 => |key| blk: {
                const signed = try key.sign(bytes, null);
                break :blk try allocator.dupe(u8, &signed.toBytes());
            },
            .ecdsa_p256 => |key| blk: {
                const signed = try key.sign(bytes, null);
                var buffer: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                break :blk try allocator.dupe(u8, signed.toDer(&buffer));
            },
        };
    }
};

pub const San = union(enum) {
    dns: []const u8,
    ip: []const u8,
};

pub const Extension = struct {
    oid: []const u8,
    value: []const u8,
    critical: bool = false,
};

pub const Options = struct {
    subject: []const u8,
    issuer: []const u8,
    serial: u8 = 1,
    is_ca: bool = false,
    omit_basic_constraints: bool = false,
    path_length: ?u8 = null,
    /// Complete BIT STRING content; null omits keyUsage.
    key_usage: ?[]const u8 = "\x07\x80",
    eku: enum { absent, server, client, both, any } = .server,
    san: ?[]const San = &.{.{ .dns = "api.example.test" }},
    san_critical: bool = false,
    not_before: []const u8 = "250101000000Z",
    not_after: []const u8 = "350101000000Z",
    extra_extensions: []const Extension = &.{},
    signature_algorithm_override: ?[]const u8 = null,
};

pub fn certificate(allocator: Allocator, subject_key: Key, issuer_key: Key, options: Options) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    var extensions: std.ArrayList([]const u8) = .empty;
    if (!options.omit_basic_constraints) {
        const path_len = if (options.path_length) |length|
            try element(scratch, 0x02, &.{length})
        else
            "";
        const basic = try element(scratch, 0x30, try join(scratch, &.{
            if (options.is_ca) "\x01\x01\xff" else "",
            path_len,
        }));
        try extensions.append(scratch, try extension(scratch, .{
            .oid = "\x55\x1d\x13",
            .value = basic,
            .critical = true,
        }));
    }
    if (options.key_usage) |usage| {
        try extensions.append(scratch, try extension(scratch, .{
            .oid = "\x55\x1d\x0f",
            .value = try element(scratch, 0x03, usage),
            .critical = true,
        }));
    }
    if (options.eku != .absent) {
        const server = "\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01";
        const client = "\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02";
        const values = switch (options.eku) {
            .server => server,
            .client => client,
            .both => server ++ client,
            .any => "\x06\x04\x55\x1d\x25\x00",
            .absent => unreachable,
        };
        try extensions.append(scratch, try extension(scratch, .{
            .oid = "\x55\x1d\x25",
            .value = try element(scratch, 0x30, values),
        }));
    }
    if (options.san) |names| {
        var encoded: std.ArrayList([]const u8) = .empty;
        for (names) |name| {
            try encoded.append(scratch, switch (name) {
                .dns => |bytes| try element(scratch, 0x82, bytes),
                .ip => |bytes| try element(scratch, 0x87, bytes),
            });
        }
        try extensions.append(scratch, try extension(scratch, .{
            .oid = "\x55\x1d\x11",
            .value = try element(scratch, 0x30, try join(scratch, encoded.items)),
            .critical = options.san_critical,
        }));
    }
    for (options.extra_extensions) |extra| try extensions.append(scratch, try extension(scratch, extra));
    const algorithm = options.signature_algorithm_override orelse issuer_key.algorithm();
    const tbs = try element(scratch, 0x30, try join(scratch, &.{
        "\xa0\x03\x02\x01\x02",
        try element(scratch, 0x02, &.{options.serial}),
        algorithm,
        try distinguishedName(scratch, options.issuer),
        try element(scratch, 0x30, try join(scratch, &.{
            try element(scratch, if (options.not_before.len == 15) 0x18 else 0x17, options.not_before),
            try element(scratch, if (options.not_after.len == 15) 0x18 else 0x17, options.not_after),
        })),
        try distinguishedName(scratch, options.subject),
        try subject_key.spki(scratch),
        try element(scratch, 0xa3, try element(scratch, 0x30, try join(scratch, extensions.items))),
    }));
    const signed = try issuer_key.sign(scratch, tbs);
    const result = try element(scratch, 0x30, try join(scratch, &.{
        tbs,
        algorithm,
        try element(scratch, 0x03, try join(scratch, &.{ "\x00", signed })),
    }));
    return allocator.dupe(u8, result);
}

fn extension(allocator: Allocator, options: Extension) ![]const u8 {
    return element(allocator, 0x30, try join(allocator, &.{
        try element(allocator, 0x06, options.oid),
        if (options.critical) "\x01\x01\xff" else "",
        try element(allocator, 0x04, options.value),
    }));
}

fn distinguishedName(allocator: Allocator, text: []const u8) ![]const u8 {
    if (text.len == 0) return element(allocator, 0x30, "");
    return element(allocator, 0x30, try element(allocator, 0x31, try element(allocator, 0x30, try join(allocator, &.{
        "\x06\x03\x55\x04\x03",
        try element(allocator, 0x0c, text),
    }))));
}

fn element(allocator: Allocator, tag: u8, content: []const u8) ![]const u8 {
    var header: [6]u8 = undefined;
    header[0] = tag;
    const header_len: usize = if (content.len < 128) blk: {
        header[1] = @intCast(content.len);
        break :blk 2;
    } else if (content.len <= 255) blk: {
        header[1] = 0x81;
        header[2] = @intCast(content.len);
        break :blk 3;
    } else blk: {
        header[1] = 0x82;
        std.mem.writeInt(u16, header[2..4], @intCast(content.len), .big);
        break :blk 4;
    };
    return join(allocator, &.{ header[0..header_len], content });
}

fn join(allocator: Allocator, parts: []const []const u8) ![]const u8 {
    var length: usize = 0;
    for (parts) |part| length += part.len;
    const result = try allocator.alloc(u8, length);
    var offset: usize = 0;
    for (parts) |part| {
        @memcpy(result[offset..][0..part.len], part);
        offset += part.len;
    }
    return result;
}

pub fn pem(allocator: Allocator, der_bytes: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(der_bytes.len));
    defer allocator.free(encoded);
    return std.fmt.allocPrint(allocator, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{
        encoder.encode(encoded, der_bytes),
    });
}

pub const Chain = struct {
    allocator: Allocator,
    root_key: Key,
    intermediate_key: Key,
    leaf_key: Key,
    root: []u8,
    intermediate: []u8,
    leaf: []u8,

    pub fn init(allocator: Allocator, scheme: Scheme) !Chain {
        const root_key = try Key.init(scheme, 1);
        const intermediate_key = try Key.init(scheme, 2);
        const leaf_key = try Key.init(scheme, 3);
        const root = try certificate(allocator, root_key, root_key, rootOptions());
        errdefer allocator.free(root);
        const intermediate = try certificate(allocator, intermediate_key, root_key, intermediateOptions());
        errdefer allocator.free(intermediate);
        const leaf = try certificate(allocator, leaf_key, intermediate_key, leafOptions());
        return .{
            .allocator = allocator,
            .root_key = root_key,
            .intermediate_key = intermediate_key,
            .leaf_key = leaf_key,
            .root = root,
            .intermediate = intermediate,
            .leaf = leaf,
        };
    }

    pub fn deinit(self: *Chain) void {
        self.allocator.free(self.root);
        self.allocator.free(self.intermediate);
        self.allocator.free(self.leaf);
        self.* = undefined;
    }
};

pub fn rootOptions() Options {
    return .{
        .subject = "Fixture Root",
        .issuer = "Fixture Root",
        .is_ca = true,
        .path_length = 1,
        .key_usage = "\x01\x06",
        .eku = .absent,
        .san = null,
    };
}

pub fn intermediateOptions() Options {
    return .{
        .subject = "Fixture Intermediate",
        .issuer = "Fixture Root",
        .serial = 2,
        .is_ca = true,
        .path_length = 0,
        .key_usage = "\x01\x06",
        .eku = .absent,
        .san = null,
    };
}

pub fn leafOptions() Options {
    return .{
        .subject = "Fixture Leaf",
        .issuer = "Fixture Intermediate",
        .serial = 3,
        .san = &.{
            .{ .dns = "api.example.test" },
            .{ .dns = "*.wild.example.test" },
            .{ .ip = "\x7f\x00\x00\x01" },
            .{ .ip = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" },
        },
    };
}
