//! Bounded, borrowing X.509 policy parser. No signatures or trust decisions
//! are delegated to std.crypto.Certificate.parse/verify.
const std = @import("std");
const der = @import("crypto/der.zig");
const trust = @import("trust.zig");
const signature = @import("cert_signature.zig");
const Error = trust.TrustError;

pub const max_extensions = 64;
pub const max_general_names = 256;

pub const Element = struct {
    tag: u8,
    encoded: []const u8,
    content: []const u8,
};

pub const Reader = struct {
    inner: der.Reader,

    pub fn init(bytes: []const u8) Reader {
        return .{ .inner = .{ .bytes = bytes } };
    }

    pub fn peek(self: Reader) ?u8 {
        return if (self.inner.offset < self.inner.bytes.len) self.inner.bytes[self.inner.offset] else null;
    }

    pub fn any(self: *Reader) Error!Element {
        const tag = self.peek() orelse return error.TlsMalformedCertificate;
        if (tag & 0x1f == 0x1f or tag == 0) return error.TlsMalformedCertificate;
        const start = self.inner.offset;
        const content = self.inner.take(tag) catch return error.TlsMalformedCertificate;
        return .{ .tag = tag, .encoded = self.inner.bytes[start..self.inner.offset], .content = content };
    }

    pub fn take(self: *Reader, tag: u8) Error!Element {
        if (self.peek() != tag) return error.TlsMalformedCertificate;
        return self.any();
    }

    pub fn finish(self: Reader) Error!void {
        self.inner.finish() catch return error.TlsMalformedCertificate;
    }
};

fn sequence(bytes: []const u8) Error!Reader {
    var outer = Reader.init(bytes);
    const result = try outer.take(0x30);
    try outer.finish();
    return Reader.init(result.content);
}

pub const Certificate = struct {
    der_bytes: []const u8,
    tbs: []const u8,
    algorithm: signature.AlgorithmIdentifier,
    signature_bytes: []const u8,
    issuer: []const u8,
    subject: []const u8,
    spki: []const u8,
    not_before: i64,
    not_after: i64,
    is_ca: bool = false,
    path_length: ?u32 = null,
    key_usage: ?u16 = null,
    eku: ?u8 = null,
    san: ?[]const u8 = null,
    san_critical: bool = false,
    subject_key_id: ?[]const u8 = null,
    authority_key_id: ?[]const u8 = null,
    unhandled_critical: bool = false,
    unsupported_constraints: bool = false,
    weak_key: bool = false,

    pub fn selfIssued(self: Certificate) bool {
        return std.mem.eql(u8, self.issuer, self.subject);
    }

    pub fn checkPolicy(self: Certificate, now: i64, role: trust.PeerRole, issuer: bool, ca_below: usize) Error!void {
        if (self.unhandled_critical or self.unsupported_constraints)
            return error.TlsCertificateConstraintViolation;
        if (now < self.not_before) return error.TlsCertificateNotYetValid;
        if (now > self.not_after) return error.TlsCertificateExpired;
        if (self.weak_key) return error.TlsCertificateUsageInvalid;
        if (self.eku) |usage| {
            const needed: u8 = if (role == .server) 1 else 2;
            if (usage & (needed | 4) == 0) return error.TlsCertificateUsageInvalid;
        }
        if (issuer) {
            if (!self.is_ca) return error.TlsCertificateUsageInvalid;
            if (self.key_usage) |usage| {
                if (usage & 0x0400 == 0) return error.TlsCertificateUsageInvalid;
            }
            if (self.path_length) |limit| {
                if (ca_below > limit) return error.TlsCertificateConstraintViolation;
            }
        } else {
            if (self.is_ca) return error.TlsCertificateUsageInvalid;
            if (self.key_usage) |usage| {
                if (usage & 0x8000 == 0 or usage & 0x0400 != 0)
                    return error.TlsCertificateUsageInvalid;
            }
        }
    }

    pub fn checkIdentity(self: Certificate, identity: trust.PeerIdentity) Error!void {
        switch (identity) {
            .dns_name => |name| {
                const normalized = stripFinalDot(name);
                if (!validDns(normalized, false) or ipv4Literal(normalized))
                    return error.TlsInvalidTrustConfiguration;
            },
            .ip_address => {},
        }
        var names = Reader.init(self.san orelse return error.TlsHostnameMismatch);
        while (names.peek() != null) {
            const name = try names.any();
            const matches = switch (identity) {
                .dns_name => |expected| name.tag == 0x82 and dnsMatches(name.content, stripFinalDot(expected)),
                .ip_address => |ip| name.tag == 0x87 and switch (ip) {
                    .v4 => |bytes| std.mem.eql(u8, name.content, &bytes),
                    .v6 => |bytes| std.mem.eql(u8, name.content, &bytes),
                },
            };
            if (matches) return;
        }
        return error.TlsHostnameMismatch;
    }
};

pub fn parse(bytes: []const u8) Error!Certificate {
    var outer = try sequence(bytes);
    const tbs_element = try outer.take(0x30);
    const outer_algorithm = try outer.take(0x30);
    const algorithm = try parseAlgorithm(outer_algorithm.content);
    const signature_bits = try outer.take(0x03);
    try outer.finish();
    try bitString(signature_bits.content);
    if (signature_bits.content.len < 2 or signature_bits.content[0] != 0)
        return error.TlsMalformedCertificate;

    var tbs = Reader.init(tbs_element.content);
    var version: u8 = 0;
    if (tbs.peek() == 0xa0) {
        var explicit = Reader.init((try tbs.take(0xa0)).content);
        const value = (try explicit.take(0x02)).content;
        if (value.len != 1 or (value[0] != 1 and value[0] != 2)) return error.TlsMalformedCertificate;
        version = value[0];
        try explicit.finish();
    }
    const serial = (try tbs.take(0x02)).content;
    try positiveSerial(serial);
    const tbs_algorithm = try tbs.take(0x30);
    if (!std.mem.eql(u8, tbs_algorithm.encoded, outer_algorithm.encoded))
        return error.TlsMalformedCertificate;
    const issuer = try tbs.take(0x30);
    try validateName(issuer.content);
    if (issuer.content.len == 0) return error.TlsMalformedCertificate;
    var validity = Reader.init((try tbs.take(0x30)).content);
    const not_before = try parseTime(try validity.any());
    const not_after = try parseTime(try validity.any());
    try validity.finish();
    if (not_after < not_before) return error.TlsMalformedCertificate;
    const subject = try tbs.take(0x30);
    try validateName(subject.content);
    const spki = try tbs.take(0x30);
    var result: Certificate = .{
        .der_bytes = bytes,
        .tbs = tbs_element.encoded,
        .algorithm = algorithm,
        .signature_bytes = signature_bits.content[1..],
        .issuer = issuer.encoded,
        .subject = subject.encoded,
        .spki = spki.encoded,
        .not_before = not_before,
        .not_after = not_after,
        .weak_key = try weakPublicKey(spki.content),
    };
    if (tbs.peek() == 0x81) {
        if (version == 0) return error.TlsMalformedCertificate;
        try bitString((try tbs.take(0x81)).content);
    }
    if (tbs.peek() == 0x82) {
        if (version == 0) return error.TlsMalformedCertificate;
        try bitString((try tbs.take(0x82)).content);
    }
    if (tbs.peek() == 0xa3) {
        if (version != 2) return error.TlsMalformedCertificate;
        try parseExtensions(&result, (try tbs.take(0xa3)).content);
    }
    try tbs.finish();
    if (subject.content.len == 0 and (result.san == null or !result.san_critical))
        return error.TlsMalformedCertificate;
    return result;
}

fn parseAlgorithm(bytes: []const u8) Error!signature.AlgorithmIdentifier {
    var reader = Reader.init(bytes);
    const oid = (try reader.take(0x06)).content;
    try validateOid(oid);
    const parameters = if (reader.peek() != null) (try reader.any()).encoded else null;
    try reader.finish();
    return .{ .oid = oid, .parameters_der = parameters };
}

pub fn strongSignature(algorithm: signature.AlgorithmIdentifier) bool {
    for ([_][]const u8{
        "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b",
        "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c",
        "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d",
        "\x2a\x86\x48\xce\x3d\x04\x03\x02",
        "\x2a\x86\x48\xce\x3d\x04\x03\x03",
        "\x2b\x65\x70",
    }) |oid| {
        if (std.mem.eql(u8, algorithm.oid, oid)) return true;
    }
    return false;
}

fn weakPublicKey(bytes: []const u8) Error!bool {
    var reader = Reader.init(bytes);
    const algorithm = try parseAlgorithm((try reader.take(0x30)).content);
    const bits = (try reader.take(0x03)).content;
    try reader.finish();
    try bitString(bits);
    if (bits.len < 2 or bits[0] != 0) return error.TlsMalformedCertificate;
    if (std.mem.eql(u8, algorithm.oid, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")) {
        if (algorithm.parameters_der) |params| {
            if (!std.mem.eql(u8, params, "\x05\x00")) return error.TlsMalformedCertificate;
        }
        var rsa = der.sequence(bits[1..]) catch return error.TlsMalformedCertificate;
        const modulus = der.positiveInteger(&rsa) catch return error.TlsMalformedCertificate;
        const exponent = der.positiveInteger(&rsa) catch return error.TlsMalformedCertificate;
        rsa.finish() catch return error.TlsMalformedCertificate;
        if (exponent.len > 4 or exponent.len == 0 or exponent[exponent.len - 1] & 1 == 0)
            return error.TlsMalformedCertificate;
        return modulus.len < 256 or (modulus.len == 256 and modulus[0] & 0x80 == 0) or
            (exponent.len == 1 and exponent[0] < 3);
    }
    if (std.mem.eql(u8, algorithm.oid, "\x2a\x86\x48\xce\x3d\x02\x01")) {
        var curve = Reader.init(algorithm.parameters_der orelse return error.TlsMalformedCertificate);
        const oid = (try curve.take(0x06)).content;
        try curve.finish();
        const length: usize = if (std.mem.eql(u8, oid, "\x2a\x86\x48\xce\x3d\x03\x01\x07"))
            65
        else if (std.mem.eql(u8, oid, "\x2b\x81\x04\x00\x22"))
            97
        else
            return true;
        if (bits.len != length + 1 or bits[1] != 4) return error.TlsMalformedCertificate;
        return false;
    }
    if (std.mem.eql(u8, algorithm.oid, "\x2b\x65\x70")) {
        if (algorithm.parameters_der != null or bits.len != 33) return error.TlsMalformedCertificate;
        return false;
    }
    return true;
}

fn parseExtensions(cert: *Certificate, bytes: []const u8) Error!void {
    var extensions = try sequence(bytes);
    var seen: [max_extensions][]const u8 = undefined;
    var count: usize = 0;
    if (extensions.peek() == null) return error.TlsMalformedCertificate;
    while (extensions.peek() != null) {
        if (count == seen.len) return error.TlsCertificateConstraintViolation;
        var extension = Reader.init((try extensions.take(0x30)).content);
        const oid = (try extension.take(0x06)).content;
        try validateOid(oid);
        for (seen[0..count]) |prior| {
            if (std.mem.eql(u8, prior, oid)) return error.TlsMalformedCertificate;
        }
        seen[count] = oid;
        count += 1;
        var critical = false;
        if (extension.peek() == 0x01) {
            const value = (try extension.take(0x01)).content;
            if (!std.mem.eql(u8, value, "\xff")) return error.TlsMalformedCertificate;
            critical = true;
        }
        const value = (try extension.take(0x04)).content;
        try extension.finish();
        if (std.mem.eql(u8, oid, "\x55\x1d\x13")) {
            var constraints = try sequence(value);
            if (constraints.peek() == 0x01) {
                if (!std.mem.eql(u8, (try constraints.take(0x01)).content, "\xff"))
                    return error.TlsMalformedCertificate;
                cert.is_ca = true;
            }
            if (constraints.peek() == 0x02) {
                if (!cert.is_ca) return error.TlsMalformedCertificate;
                cert.path_length = try nonnegativeInteger((try constraints.take(0x02)).content);
            }
            try constraints.finish();
        } else if (std.mem.eql(u8, oid, "\x55\x1d\x0f")) {
            var usage = Reader.init(value);
            const bits = (try usage.take(0x03)).content;
            try usage.finish();
            try bitString(bits);
            if (bits.len < 2 or bits.len > 3 or bits[bits.len - 1] == 0 or
                @ctz(bits[bits.len - 1]) != bits[0] or (bits.len == 3 and bits[2] != 0x80))
                return error.TlsMalformedCertificate;
            const mask = @as(u16, bits[1]) << 8 | if (bits.len == 3) @as(u16, bits[2]) else 0;
            if (mask & 0x0180 != 0 and mask & 0x0800 == 0) return error.TlsMalformedCertificate;
            cert.key_usage = mask;
        } else if (std.mem.eql(u8, oid, "\x55\x1d\x25")) {
            var usage = try sequence(value);
            if (usage.peek() == null) return error.TlsMalformedCertificate;
            var mask: u8 = 0;
            var entries: usize = 0;
            while (usage.peek() != null) {
                entries += 1;
                if (entries > max_general_names) return error.TlsCertificateConstraintViolation;
                const purpose = (try usage.take(0x06)).content;
                try validateOid(purpose);
                if (std.mem.eql(u8, purpose, "\x2b\x06\x01\x05\x05\x07\x03\x01")) mask |= 1;
                if (std.mem.eql(u8, purpose, "\x2b\x06\x01\x05\x05\x07\x03\x02")) mask |= 2;
                if (std.mem.eql(u8, purpose, "\x55\x1d\x25\x00")) mask |= 4;
            }
            cert.eku = mask;
        } else if (std.mem.eql(u8, oid, "\x55\x1d\x11")) {
            const names = try sequence(value);
            cert.san = names.inner.bytes;
            cert.san_critical = critical;
            const unsupported = try validateGeneralNames(names.inner.bytes);
            if (critical and unsupported) cert.unhandled_critical = true;
        } else if (std.mem.eql(u8, oid, "\x55\x1d\x0e")) {
            var key_id = Reader.init(value);
            cert.subject_key_id = (try key_id.take(0x04)).content;
            if (cert.subject_key_id.?.len == 0) return error.TlsMalformedCertificate;
            try key_id.finish();
            if (critical) cert.unhandled_critical = true;
        } else if (std.mem.eql(u8, oid, "\x55\x1d\x23")) {
            var key_id = try sequence(value);
            if (key_id.peek() == null) return error.TlsMalformedCertificate;
            if (key_id.peek() == 0x80) {
                cert.authority_key_id = (try key_id.take(0x80)).content;
                if (cert.authority_key_id.?.len == 0) return error.TlsMalformedCertificate;
            }
            if (key_id.peek() == 0xa1) {
                _ = try validateGeneralNames((try key_id.take(0xa1)).content);
                try positiveSerial((try key_id.take(0x82)).content);
            }
            try key_id.finish();
            if (critical) cert.unhandled_critical = true;
        } else if (std.mem.eql(u8, oid, "\x55\x1d\x1e") or
            std.mem.eql(u8, oid, "\x55\x1d\x21") or
            std.mem.eql(u8, oid, "\x55\x1d\x24") or
            std.mem.eql(u8, oid, "\x55\x1d\x36"))
        {
            // Name/policy constraints cannot be ignored even if incorrectly
            // marked noncritical. This profile does not implement them.
            cert.unsupported_constraints = true;
        } else if (critical) {
            cert.unhandled_critical = true;
        }
    }
}

fn validateGeneralNames(bytes: []const u8) Error!bool {
    var names = Reader.init(bytes);
    var count: usize = 0;
    var unsupported = false;
    if (names.peek() == null) return error.TlsMalformedCertificate;
    while (names.peek() != null) {
        count += 1;
        if (count > max_general_names) return error.TlsCertificateConstraintViolation;
        const name = try names.any();
        switch (name.tag) {
            0x82 => if (!validDns(name.content, true)) return error.TlsMalformedCertificate,
            0x87 => if (name.content.len != 4 and name.content.len != 16) return error.TlsMalformedCertificate,
            0x81, 0x86 => {
                for (name.content) |byte| {
                    if (byte == 0 or byte >= 128) return error.TlsMalformedCertificate;
                }
                unsupported = true;
            },
            0xa4 => {
                const dn = try sequence(name.content);
                try validateName(dn.inner.bytes);
                unsupported = true;
            },
            0x88 => {
                try validateOid(name.content);
                unsupported = true;
            },
            0xa0, 0xa3, 0xa5 => {
                if (name.content.len == 0) return error.TlsMalformedCertificate;
                try validateConstructed(name.content, 0);
                unsupported = true;
            },
            else => return error.TlsMalformedCertificate,
        }
    }
    return unsupported;
}

fn validateOid(bytes: []const u8) Error!void {
    if (bytes.len == 0 or bytes.len > 128 or bytes[bytes.len - 1] & 0x80 != 0)
        return error.TlsMalformedCertificate;
    var first = true;
    for (bytes) |byte| {
        if (first and byte == 0x80) return error.TlsMalformedCertificate;
        first = byte & 0x80 == 0;
    }
}

fn validateConstructed(bytes: []const u8, depth: usize) Error!void {
    if (depth == 8) return error.TlsCertificateConstraintViolation;
    var elements = Reader.init(bytes);
    while (elements.peek() != null) {
        const element = try elements.any();
        if (element.tag & 0x20 != 0) try validateConstructed(element.content, depth + 1);
    }
}

fn validateName(bytes: []const u8) Error!void {
    var name = Reader.init(bytes);
    var attributes: usize = 0;
    while (name.peek() != null) {
        var rdn = Reader.init((try name.take(0x31)).content);
        if (rdn.peek() == null) return error.TlsMalformedCertificate;
        var previous: ?[]const u8 = null;
        while (rdn.peek() != null) {
            attributes += 1;
            if (attributes > max_general_names) return error.TlsCertificateConstraintViolation;
            const entry = try rdn.take(0x30);
            if (previous) |prior| {
                if (std.mem.order(u8, prior, entry.encoded) == .gt) return error.TlsMalformedCertificate;
            }
            previous = entry.encoded;
            var attribute = Reader.init(entry.content);
            try validateOid((try attribute.take(0x06)).content);
            const value = try attribute.any();
            if (value.content.len == 0) return error.TlsMalformedCertificate;
            switch (value.tag) {
                0x0c => {
                    if (!std.unicode.utf8ValidateSlice(value.content) or std.mem.indexOfScalar(u8, value.content, 0) != null)
                        return error.TlsMalformedCertificate;
                },
                0x13 => for (value.content) |byte| {
                    if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, " '()+,-./:=?", byte) == null)
                        return error.TlsMalformedCertificate;
                },
                0x16 => for (value.content) |byte| {
                    if (byte < 0x20 or byte >= 128) return error.TlsMalformedCertificate;
                },
                0x14 => return error.TlsCertificateConstraintViolation,
                0x1e, 0x1c => {
                    const width: usize = if (value.tag == 0x1e) 2 else 4;
                    if (value.content.len % width != 0) return error.TlsMalformedCertificate;
                    var offset: usize = 0;
                    while (offset < value.content.len) : (offset += width) {
                        const scalar: u32 = if (width == 2)
                            std.mem.readInt(u16, value.content[offset..][0..2], .big)
                        else
                            std.mem.readInt(u32, value.content[offset..][0..4], .big);
                        if (scalar == 0 or scalar > 0x10ffff or (scalar >= 0xd800 and scalar <= 0xdfff))
                            return error.TlsMalformedCertificate;
                    }
                },
                else => return error.TlsMalformedCertificate,
            }
            try attribute.finish();
        }
    }
}

fn positiveSerial(bytes: []const u8) Error!void {
    if (bytes.len == 0 or bytes.len > 21 or bytes[0] & 0x80 != 0) return error.TlsMalformedCertificate;
    const content = if (bytes[0] == 0) blk: {
        if (bytes.len == 1 or bytes[1] & 0x80 == 0) return error.TlsMalformedCertificate;
        break :blk bytes[1..];
    } else bytes;
    if (content.len > 20) return error.TlsMalformedCertificate;
}

fn nonnegativeInteger(bytes: []const u8) Error!u32 {
    if (bytes.len == 0 or bytes.len > 5 or bytes[0] & 0x80 != 0 or
        (bytes.len > 1 and bytes[0] == 0 and bytes[1] & 0x80 == 0))
        return error.TlsMalformedCertificate;
    var result: u32 = 0;
    for (bytes) |byte| {
        result = std.math.mul(u32, result, 256) catch return error.TlsMalformedCertificate;
        result = std.math.add(u32, result, byte) catch return error.TlsMalformedCertificate;
    }
    return result;
}

fn bitString(bytes: []const u8) Error!void {
    if (bytes.len == 0 or bytes[0] > 7) return error.TlsMalformedCertificate;
    if (bytes.len == 1) {
        if (bytes[0] != 0) return error.TlsMalformedCertificate;
    } else if (bytes[bytes.len - 1] & ((@as(u8, 1) << @as(u3, @intCast(bytes[0]))) - 1) != 0) {
        return error.TlsMalformedCertificate;
    }
}

fn decimal(bytes: []const u8) Error!i64 {
    var result: i64 = 0;
    for (bytes) |byte| {
        if (byte < '0' or byte > '9') return error.TlsMalformedCertificate;
        result = result * 10 + byte - '0';
    }
    return result;
}

pub fn parseTime(element: Element) Error!i64 {
    const bytes = element.content;
    const year_len: usize = switch (element.tag) {
        0x17 => 2,
        0x18 => 4,
        else => return error.TlsMalformedCertificate,
    };
    if (bytes.len != year_len + 11 or bytes[bytes.len - 1] != 'Z') return error.TlsMalformedCertificate;
    var year = try decimal(bytes[0..year_len]);
    if (year_len == 2) year += if (year >= 50) @as(i64, 1900) else 2000;
    if (year == 0) return error.TlsMalformedCertificate;
    const month = try decimal(bytes[year_len..][0..2]);
    const day = try decimal(bytes[year_len + 2 ..][0..2]);
    const hour = try decimal(bytes[year_len + 4 ..][0..2]);
    const minute = try decimal(bytes[year_len + 6 ..][0..2]);
    const second = try decimal(bytes[year_len + 8 ..][0..2]);
    if (month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59)
        return error.TlsMalformedCertificate;
    const leap = @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
    const month_days = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const max_day = @as(i64, month_days[@intCast(month - 1)]) + @as(i64, @intFromBool(month == 2 and leap));
    if (day < 1 or day > max_day) return error.TlsMalformedCertificate;
    const y = year - @as(i64, @intFromBool(month <= 2));
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const adjusted_month = month + if (month > 2) @as(i64, -3) else 9;
    const doy = @divFloor(153 * adjusted_month + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return (era * 146097 + doe - 719468) * 86400 + hour * 3600 + minute * 60 + second;
}

fn stripFinalDot(name: []const u8) []const u8 {
    return if (name.len > 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
}

fn validDns(name: []const u8, wildcard: bool) bool {
    if (name.len == 0 or name.len > 253) return false;
    var labels = std.mem.splitScalar(u8, name, '.');
    var index: usize = 0;
    while (labels.next()) |label| : (index += 1) {
        if (label.len == 0 or label.len > 63) return false;
        if (wildcard and index == 0 and std.mem.eql(u8, label, "*")) continue;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and byte != '-') return false;
        }
    }
    return !(wildcard and name[0] == '*' and index < 3);
}

fn ipv4Literal(name: []const u8) bool {
    var labels = std.mem.splitScalar(u8, name, '.');
    var count: usize = 0;
    while (labels.next()) |label| {
        _ = std.fmt.parseInt(u8, label, 10) catch return false;
        count += 1;
    }
    return count == 4;
}

fn dnsMatches(pattern: []const u8, expected: []const u8) bool {
    if (std.mem.startsWith(u8, pattern, "*.")) {
        const dot = std.mem.indexOfScalar(u8, expected, '.') orelse return false;
        if (std.ascii.startsWithIgnoreCase(expected[0..dot], "xn--")) return false;
        return std.ascii.eqlIgnoreCase(pattern[1..], expected[dot..]);
    }
    return std.ascii.eqlIgnoreCase(pattern, expected);
}

test "policy DNS wildcard and literal matching is strict" {
    const t = std.testing;
    try t.expect(validDns("*.example.test", true));
    try t.expect(!validDns("*.test", true));
    try t.expect(!validDns("f*.example.test", true));
    try t.expect(!validDns("a..test", false));
    try t.expect(dnsMatches("*.example.test", "API.EXAMPLE.TEST"));
    try t.expect(!dnsMatches("*.example.test", "example.test"));
    try t.expect(!dnsMatches("*.example.test", "a.b.example.test"));
    try t.expect(!dnsMatches("*.example.test", "xn--example.example.test"));
    try t.expect(ipv4Literal("127.0.0.1"));
}

test "policy time parser validates UTC generalized leap and boundary dates" {
    const t = std.testing;
    try t.expectEqual(@as(i64, 0), try parseTime(.{ .tag = 0x17, .content = "700101000000Z", .encoded = "" }));
    try t.expectEqual(@as(i64, -1), try parseTime(.{ .tag = 0x17, .content = "691231235959Z", .encoded = "" }));
    try t.expectEqual(@as(i64, 951782400), try parseTime(.{ .tag = 0x18, .content = "20000229000000Z", .encoded = "" }));
    for ([_][]const u8{ "230229000000Z", "241301000000Z", "240101240000Z", "240101000060Z", "240101000000+0000", "240000000000Z" }) |bytes| {
        try t.expectError(error.TlsMalformedCertificate, parseTime(.{ .tag = 0x17, .content = bytes, .encoded = "" }));
    }
}
