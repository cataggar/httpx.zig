//! Approved test-only MD5/native metadata conformance. No store is opened,
//! no certificate/CTL is persisted, and no native signature/chain is verified.
//! Generic CertFindSubjectInCTL results are not Windows chain-policy results.
//! CTL_ANY_SUBJECT_TYPE matches opaque bytes: a compound control matching that
//! path does not establish a compound disallowed-identifier encoding.
//! Algorithm-only PSS/MD5/unknown fixtures deliberately carry no valid signature
//! under those algorithms; they exercise metadata decoding, not authentication.
const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const crypt32 = windows.crypt32;
const certificates = @import("trust_fixtures.zig");
const fixture = @import("ctl_fixtures.zig");
const Reader = @import("x509_policy.zig").Reader;
const Allocator = std.mem.Allocator;
const certificate_encoding: crypt32.ENCODING.TYPE = .{ .CERT = .ASN };
const ctl_encoding: crypt32.ENCODING.TYPE = .{ .CERT = .ASN, .CMSG = .ASN };
const max_certificate_bytes = 4096;
const max_identifier_bytes = 128;
const not_found = 0x80092004;

const Ctl = opaque {};
const CtlEntry = opaque {};
const Blob = extern struct { length: u32, bytes: ?[*]const u8 };
const AlgorithmIdentifier = extern struct { oid: [*:0]const u8, parameters: Blob };
const AnySubject = extern struct { algorithm: AlgorithmIdentifier, identifier: Blob };

extern "crypt32" fn CertCreateCertificateContext(crypt32.ENCODING.TYPE, [*]const u8, u32) callconv(.winapi) ?*const crypt32.CERT_CONTEXT;
extern "crypt32" fn CertGetCertificateContextProperty(*const crypt32.CERT_CONTEXT, u32, ?*anyopaque, *u32) callconv(.winapi) windows.BOOL;
extern "crypt32" fn CryptHashToBeSigned(usize, crypt32.ENCODING.TYPE, [*]const u8, u32, ?*anyopaque, *u32) callconv(.winapi) windows.BOOL;
extern "crypt32" fn CertCreateCTLContext(crypt32.ENCODING.TYPE, [*]const u8, u32) callconv(.winapi) ?*const Ctl;
extern "crypt32" fn CertFreeCTLContext(*const Ctl) callconv(.winapi) windows.BOOL;
extern "crypt32" fn CertFindSubjectInCTL(crypt32.ENCODING.TYPE, u32, *const anyopaque, *const Ctl, u32) callconv(.winapi) ?*const CtlEntry;

const Case = enum { sha256_a, sha256_b, sha384, pss_sha256_only, pss_defaults_only, pss_absent_only, legacy_md5_only, unknown_only, rsa_subject_sha256, rsa_subject_sha384, ed25519_signature };
const Domain = enum { full_der, tbs_der, tbs_contents, signature_bits, public_key_bits, spki_der, public_key_bit_string_contents, public_key_bit_string_der };
const ReferenceHash = enum { md5, sha1, sha256, sha384, sha512 };
const Domains = [8][]const u8;
const Certificate = struct { name: Case, bytes: []const u8, domains: Domains };

fn sequence(bytes: []const u8) !Reader {
    var outer = Reader.init(bytes);
    const value = try outer.take(0x30);
    try outer.finish();
    return Reader.init(value.content);
}

fn domains(bytes: []const u8) !Domains {
    if (bytes.len > max_certificate_bytes) return error.TestUnexpectedResult;
    var certificate = try sequence(bytes);
    const tbs = try certificate.take(0x30);
    _ = try certificate.take(0x30);
    const signature = (try certificate.take(0x03)).content;
    try certificate.finish();
    if (signature.len < 2 or signature[0] != 0) return error.TestUnexpectedResult;
    var fields = Reader.init(tbs.content);
    _ = try fields.take(0xa0);
    _ = try fields.take(0x02);
    for (0..4) |_| _ = try fields.take(0x30);
    const spki = try fields.take(0x30);
    _ = try fields.take(0xa3);
    try fields.finish();
    var key = Reader.init(spki.content);
    _ = try key.take(0x30);
    const bit_string = try key.take(0x03);
    const bits = bit_string.content;
    try key.finish();
    if (bits.len < 2 or bits[0] != 0) return error.TestUnexpectedResult;
    return .{ bytes, tbs.encoded, tbs.content, signature[1..], bits[1..], spki.encoded, bits, bit_string.encoded };
}

fn pssAlgorithm(a: Allocator) ![]const u8 {
    const hash = "\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00";
    const mgf = try fixture.element(a, 0x30, try fixture.join(a, &.{ "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08", hash }));
    const parameters = try fixture.element(a, 0x30, try fixture.join(a, &.{
        try fixture.element(a, 0xa0, hash),
        try fixture.element(a, 0xa1, mgf),
        "\xa2\x03\x02\x01\x20",
    }));
    return fixture.element(a, 0x30, try fixture.join(a, &.{ "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a", parameters }));
}

fn rsaSubject(a: Allocator, bytes: []const u8, algorithm: []const u8, issuer: certificates.Key) ![]const u8 {
    const parts = try domains(bytes);
    var tbs = try sequence(parts[@intFromEnum(Domain.tbs_der)]);
    _ = try tbs.take(0xa0);
    _ = try tbs.take(0x02);
    for (0..4) |_| _ = try tbs.take(0x30);
    const start = tbs.inner.offset;
    _ = try tbs.take(0x30);
    // A public RSA encoding control, not a private key or a claim about RSA
    // signing. The synthetic issuer signs this leaf with ECDSA.
    const public_key = try fixture.element(a, 0x30, try fixture.join(a, &.{
        try fixture.element(a, 0x02, "\x00\x80" ++ ("\x01" ** 255)),
        "\x02\x03\x01\x00\x01",
    }));
    const spki = try fixture.element(a, 0x30, try fixture.join(a, &.{
        "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00",
        try fixture.element(a, 0x03, try fixture.join(a, &.{ "\x00", public_key })),
    }));
    const encoded = try fixture.element(a, 0x30, try fixture.join(a, &.{
        tbs.inner.bytes[0..start], spki, tbs.inner.bytes[tbs.inner.offset..],
    }));
    const signed = try issuer.ecdsa_p256.sign(encoded, null);
    var buffer: [std.crypto.sign.ecdsa.EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    return fixture.element(a, 0x30, try fixture.join(a, &.{
        encoded, algorithm, try fixture.element(a, 0x03, try fixture.join(a, &.{ "\x00", signed.toDer(&buffer) })),
    }));
}

fn makeCertificates(a: Allocator) ![11]Certificate {
    const sha256_algorithm = "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";
    const sha384_algorithm = "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03";
    const cases = [_]struct { name: Case, algorithm: []const u8 }{
        .{ .name = .sha256_a, .algorithm = sha256_algorithm },
        .{ .name = .sha256_b, .algorithm = sha256_algorithm },
        .{ .name = .sha384, .algorithm = sha384_algorithm },
        .{ .name = .pss_sha256_only, .algorithm = try pssAlgorithm(a) },
        .{ .name = .pss_defaults_only, .algorithm = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x00" },
        .{ .name = .pss_absent_only, .algorithm = "\x30\x0b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a" },
        .{ .name = .legacy_md5_only, .algorithm = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04\x05\x00" },
        .{ .name = .unknown_only, .algorithm = "\x30\x05\x06\x03\x2a\x03\x04" },
        .{ .name = .rsa_subject_sha256, .algorithm = sha256_algorithm },
        .{ .name = .rsa_subject_sha384, .algorithm = sha384_algorithm },
        .{ .name = .ed25519_signature, .algorithm = "\x30\x05\x06\x03\x2b\x65\x70" },
    };
    const subject = try certificates.Key.init(.ecdsa_p256, 0x31);
    const issuer = try certificates.Key.init(.ecdsa_p256, 0x32);
    var result: [11]Certificate = undefined;
    for (cases, 0..) |case, index| {
        if (@intFromEnum(case.name) != index) return error.TestUnexpectedResult;
        const algorithm = case.algorithm;
        const signer = if (case.name == .ed25519_signature) try certificates.Key.init(.ed25519, 0x34) else issuer;
        var bytes: []const u8 = try certificates.certificate(a, subject, signer, .{
            .subject = "conformance leaf",
            .issuer = "conformance issuer",
            .serial = @intCast(index + 1),
            .signature_algorithm_override = algorithm,
        });
        if (index == @intFromEnum(Case.rsa_subject_sha256) or index == @intFromEnum(Case.rsa_subject_sha384))
            bytes = try rsaSubject(a, bytes, algorithm, issuer);
        if (index == @intFromEnum(Case.sha384) or index == @intFromEnum(Case.rsa_subject_sha384)) {
            const parts = try domains(bytes);
            const key = try std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair.generateDeterministic(@splat(0x33));
            const signed = try key.sign(parts[@intFromEnum(Domain.tbs_der)], null);
            var buffer: [std.crypto.sign.ecdsa.EcdsaP384Sha384.Signature.der_encoded_length_max]u8 = undefined;
            bytes = try fixture.element(a, 0x30, try fixture.join(a, &.{
                parts[@intFromEnum(Domain.tbs_der)],
                algorithm,
                try fixture.element(a, 0x03, try fixture.join(a, &.{ "\x00", signed.toDer(&buffer) })),
            }));
        }
        result[index] = .{ .name = case.name, .bytes = bytes, .domains = try domains(bytes) };
    }
    return result;
}

const Value = struct {
    state: enum { not_called, present, failed, oversized } = .not_called,
    code: u32 = 0,
    length: usize = 0,
    bytes: [64]u8 = @splat(0),

    fn finish(self: *Value, success: bool, length: u32, code: u32) void {
        self.code = if (success) 0 else code;
        self.state = if (length > self.bytes.len) .oversized else if (success) .present else .failed;
        self.length = if (self.state == .present) length else 0;
        if (self.state != .present) @memset(&self.bytes, 0);
    }

    fn equal(self: Value, other: Value) bool {
        return self.state == .present and other.state == .present and self.length == other.length and
            std.mem.eql(u8, self.bytes[0..self.length], other.bytes[0..other.length]);
    }
};

fn reference(algorithm: ReferenceHash, bytes: []const u8) Value {
    var result = Value{ .state = .present };
    switch (algorithm) {
        inline else => |tag| {
            const Hash = switch (tag) {
                .md5 => std.crypto.hash.Md5,
                .sha1 => std.crypto.hash.Sha1,
                .sha256 => std.crypto.hash.sha2.Sha256,
                .sha384 => std.crypto.hash.sha2.Sha384,
                .sha512 => std.crypto.hash.sha2.Sha512,
            };
            var digest: [Hash.digest_length]u8 = undefined;
            Hash.hash(bytes, &digest, .{});
            @memcpy(result.bytes[0..digest.len], &digest);
            result.length = digest.len;
        },
    }
    return result;
}

fn matches(value: Value, parts: Domains, algorithm: ReferenceHash) [8]bool {
    var result: [8]bool = undefined;
    for (parts, 0..) |bytes, index| result[index] = value.equal(reference(algorithm, bytes));
    return result;
}

fn property(context: *const crypt32.CERT_CONTEXT, id: u32) Value {
    var result = Value{};
    var length: u32 = result.bytes.len;
    const success = CertGetCertificateContextProperty(context, id, &result.bytes, &length).toBool();
    const code = if (success) 0 else @intFromEnum(windows.GetLastError());
    result.finish(success, length, code);
    return result;
}

fn nativeTbs(bytes: []const u8) Value {
    var result = Value{};
    var length: u32 = result.bytes.len;
    const success = CryptHashToBeSigned(0, certificate_encoding, bytes.ptr, @intCast(bytes.len), &result.bytes, &length).toBool();
    const code = if (success) 0 else @intFromEnum(windows.GetLastError());
    result.finish(success, length, code);
    return result;
}

const Observation = struct {
    context: ?*const crypt32.CERT_CONTEXT = null,
    signature: Value = .{},
    key: Value = .{},
    direct_tbs: Value = .{},
};

const Selector = struct { name: enum { sha1, md5, sha256, property15, property25 }, oid: []const u8, text: [:0]const u8 };
const selectors = [_]Selector{
    .{ .name = .sha1, .oid = "\x2b\x0e\x03\x02\x1a", .text = "1.3.14.3.2.26" },
    .{ .name = .md5, .oid = "\x2a\x86\x48\x86\xf7\x0d\x02\x05", .text = "1.2.840.113549.2.5" },
    .{ .name = .sha256, .oid = "\x60\x86\x48\x01\x65\x03\x04\x02\x01", .text = "2.16.840.1.101.3.4.2.1" },
    .{ .name = .property15, .oid = "\x2b\x06\x01\x04\x01\x82\x37\x0a\x0b\x0f", .text = "1.3.6.1.4.1.311.10.11.15" },
    .{ .name = .property25, .oid = "\x2b\x06\x01\x04\x01\x82\x37\x0a\x0b\x19", .text = "1.3.6.1.4.1.311.10.11.25" },
};

const CandidateName = enum { full_sha1, full_md5, full_sha256, native15_a, native25_a, native15_sha384, signature_then_key, key_then_signature, wrong_signature };
const Candidate = struct {
    name: CandidateName,
    available: bool = false,
    bytes: [max_identifier_bytes]u8 = @splat(0),
    length: usize = 0,

    fn from(name: CandidateName, first: Value, second: ?Value) Candidate {
        var result = Candidate{ .name = name };
        if (first.state != .present) return result;
        if (second) |value| {
            if (value.state != .present) return result;
        }
        result.available = true;
        @memcpy(result.bytes[0..first.length], first.bytes[0..first.length]);
        result.length = first.length;
        if (second) |value| {
            @memcpy(result.bytes[result.length..][0..value.length], value.bytes[0..value.length]);
            result.length += value.length;
        }
        return result;
    }
};

fn ctlEnvelope(a: Allocator, selector: Selector, null_parameters: bool, candidate: Candidate) ![]const u8 {
    const content = try fixture.element(a, 0x30, try fixture.join(a, &.{
        try fixture.element(a, 0x30, try fixture.element(a, 0x06, @import("windows_ctl.zig").disallowed_usage)),
        "\x17\x0d250101000000Z",
        "\x17\x0d350101000000Z",
        try fixture.element(a, 0x30, try fixture.join(a, &.{ try fixture.element(a, 0x06, selector.oid), if (null_parameters) "\x05\x00" else "" })),
        try fixture.element(a, 0x30, try fixture.element(a, 0x30, try fixture.element(a, 0x04, candidate.bytes[0..candidate.length]))),
    }));
    const encoded = try fixture.envelope(a, content);
    if (encoded.len > max_certificate_bytes) return error.TestUnexpectedResult;
    return encoded;
}

const Lookup = struct {
    state: enum { not_called, matched, not_found, failed } = .not_called,
    code: u32 = 0,
};

fn find(ctl: *const Ctl, subject_type: u32, subject: *const anyopaque) Lookup {
    if (CertFindSubjectInCTL(ctl_encoding, subject_type, subject, ctl, 0) != null) return .{ .state = .matched };
    const code = @intFromEnum(windows.GetLastError());
    return .{ .state = if (code == not_found) .not_found else .failed, .code = code };
}

fn anySubject(selector: Selector, null_parameters: bool, candidate: *const Candidate) AnySubject {
    return .{
        .algorithm = .{ .oid = selector.text, .parameters = .{
            .length = if (null_parameters) 2 else 0,
            .bytes = if (null_parameters) "\x05\x00" else null,
        } },
        .identifier = .{ .length = @intCast(candidate.length), .bytes = candidate.bytes[0..candidate.length].ptr },
    };
}

fn lookupMatrix(a: Allocator, certs: []const Certificate, observations: []const Observation) !bool {
    const first = observations[0];
    var candidates = [_]Candidate{
        .from(.full_sha1, reference(.sha1, certs[0].bytes), null),
        .from(.full_md5, reference(.md5, certs[0].bytes), null),
        .from(.full_sha256, reference(.sha256, certs[0].bytes), null),
        .from(.native15_a, first.signature, null),
        .from(.native25_a, first.key, null),
        .from(.native15_sha384, observations[2].signature, null),
        .from(.signature_then_key, first.signature, first.key),
        .from(.key_then_signature, first.key, first.signature),
        .from(.wrong_signature, first.signature, null),
    };
    if (candidates[8].available and candidates[8].length != 0) candidates[8].bytes[0] ^= 1;
    var valid = true;
    var count: usize = 0;
    for (selectors) |selector| {
        for ([_]bool{ false, true }) |null_parameters| {
            for (&candidates) |*candidate| {
                count += 1;
                if (!candidate.available) {
                    std.debug.print("Disallowed conformance lookup selector={s} null_params={} candidate={s} unavailable\n", .{ @tagName(selector.name), null_parameters, @tagName(candidate.name) });
                    valid = false;
                    continue;
                }
                const encoded = try ctlEnvelope(a, selector, null_parameters, candidate.*);
                const ctl = CertCreateCTLContext(ctl_encoding, encoded.ptr, @intCast(encoded.len)) orelse {
                    const code = @intFromEnum(windows.GetLastError());
                    std.debug.print("Disallowed conformance lookup selector={s} null_params={} candidate={s} context_error={d}\n", .{ @tagName(selector.name), null_parameters, @tagName(candidate.name), code });
                    valid = false;
                    continue;
                };
                defer _ = CertFreeCTLContext(ctl);
                var by_certificate: [3]Lookup = @splat(.{});
                for (observations[0..3], 0..) |observation, index| {
                    if (observation.context) |context| by_certificate[index] = find(ctl, 2, context);
                }
                var any = anySubject(selector, null_parameters, candidate);
                const exact = find(ctl, 1, &any);
                var other_parameters_subject = anySubject(selector, !null_parameters, candidate);
                const other_parameters = find(ctl, 1, &other_parameters_subject);
                var wrong = candidate.*;
                wrong.bytes[0] ^= 1;
                any.identifier.bytes = &wrong.bytes;
                const wrong_identifier = find(ctl, 1, &any);
                any.identifier.bytes = &candidate.bytes;
                any.algorithm.oid = "1.2.3.4";
                const wrong_algorithm = find(ctl, 1, &any);
                std.debug.print("Disallowed conformance lookup selector={s} null_params={} candidate={s} length={d} certA={s}/{d} certB={s}/{d} certC={s}/{d} any_exact={s}/{d} any_other_params={s}/{d} any_wrong_id={s}/{d} any_wrong_oid={s}/{d}\n", .{
                    @tagName(selector.name),           null_parameters,        @tagName(candidate.name),          candidate.length,
                    @tagName(by_certificate[0].state), by_certificate[0].code, @tagName(by_certificate[1].state), by_certificate[1].code,
                    @tagName(by_certificate[2].state), by_certificate[2].code, @tagName(exact.state),             exact.code,
                    @tagName(other_parameters.state),  other_parameters.code,  @tagName(wrong_identifier.state),  wrong_identifier.code,
                    @tagName(wrong_algorithm.state),   wrong_algorithm.code,
                });
                valid = valid and exact.state == .matched and wrong_identifier.state != .matched and wrong_algorithm.state != .matched;
                if ((selector.name == .sha1 and candidate.name == .full_sha1) or (selector.name == .md5 and candidate.name == .full_md5))
                    valid = valid and by_certificate[0].state == .matched and by_certificate[1].state != .matched and by_certificate[2].state != .matched;
            }
        }
    }
    try std.testing.expect(count == 90);
    return valid;
}

test "disallowed conformance fixtures distinguish domains and retain valid SHA384 signing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const certs = try makeCertificates(arena.allocator());
    try std.testing.expect(std.mem.eql(u8, certs[0].domains[4], certs[1].domains[4]));
    try std.testing.expect(std.mem.eql(u8, certs[0].domains[5], certs[2].domains[5]));
    try std.testing.expect(!std.mem.eql(u8, certs[0].domains[1], certs[1].domains[1]));
    const Scheme = std.crypto.sign.ecdsa.EcdsaP384Sha384;
    const key = try Scheme.KeyPair.generateDeterministic(@splat(0x33));
    for ([_]usize{ 2, 9 }) |index| {
        const signature = try Scheme.Signature.fromDer(certs[index].domains[3]);
        try signature.verify(certs[index].domains[1], key.public_key);
    }
    try std.testing.expect(std.mem.eql(u8, certs[8].domains[4], certs[9].domains[4]));
    try std.testing.expect(certs[8].domains[4][0] == 0x30);
    for (certs) |certificate| {
        var outer = try sequence(certificate.bytes);
        _ = try outer.take(0x30);
        var algorithm = Reader.init((try outer.take(0x30)).content);
        const oid = (try algorithm.take(0x06)).content;
        const expected_oid: []const u8 = switch (certificate.name) {
            .sha256_a, .sha256_b, .rsa_subject_sha256 => "\x2a\x86\x48\xce\x3d\x04\x03\x02",
            .sha384, .rsa_subject_sha384 => "\x2a\x86\x48\xce\x3d\x04\x03\x03",
            .pss_sha256_only, .pss_defaults_only, .pss_absent_only => "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a",
            .legacy_md5_only => "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04",
            .unknown_only => "\x2a\x03\x04",
            .ed25519_signature => "\x2b\x65\x70",
        };
        try std.testing.expect(std.mem.eql(u8, oid, expected_oid));
        for (0..certificate.bytes.len) |length| {
            if (domains(certificate.bytes[0..length])) |_| return error.TestUnexpectedResult else |_| {}
        }
        for (std.enums.values(ReferenceHash)) |reference_algorithm| {
            for (certificate.domains, 0..) |bytes, index| {
                const equal = matches(reference(reference_algorithm, bytes), certificate.domains, reference_algorithm);
                try std.testing.expect(equal[index]);
                var count: usize = 0;
                for (equal) |value| count += @intFromBool(value);
                try std.testing.expect(count == 1);
            }
        }
    }
}

test "disallowed conformance bounds native outputs and fixture allocation ownership" {
    const md5 = reference(.md5, "abc");
    try std.testing.expect(md5.length == 16 and std.mem.eql(u8, md5.bytes[0..16], "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72"));
    var value = Value{};
    @memset(&value.bytes, 0xa5);
    value.finish(true, 65, 0);
    try std.testing.expect(value.state == .oversized and value.length == 0);
    try std.testing.expect(std.mem.allEqual(u8, &value.bytes, 0));
    value.finish(false, 80, 234);
    try std.testing.expect(value.state == .oversized and value.code == 234);
    try std.testing.expect(!value.equal(value));
    const Test = struct {
        fn run(a: Allocator) !void {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const certs = try makeCertificates(arena.allocator());
            const candidate = Candidate.from(.full_md5, reference(.md5, certs[0].bytes), null);
            _ = try ctlEnvelope(arena.allocator(), selectors[0], true, candidate);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
}

test "native Windows disallowed conformance observes domains and bounded generic CTL lookup" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const certs = try makeCertificates(arena.allocator());
    var observations: [11]Observation = @splat(.{});
    defer for (observations) |observation| {
        if (observation.context) |context| _ = crypt32.CertFreeCertificateContext(@constCast(context));
    };
    var valid = true;
    std.debug.print("Disallowed conformance certificates=11 ctl_cases=90 max_lookup_calls=630 domains=(full_der,tbs_der,tbs_contents,signature_bits,public_key_bits,spki_der,public_key_bit_string_contents,public_key_bit_string_der); fresh synthetic contexts only; generic lookup is NOT chain policy\n", .{});
    for (certs, &observations, 0..) |certificate, *observation, index| {
        observation.context = CertCreateCertificateContext(certificate_encoding, certificate.bytes.ptr, @intCast(certificate.bytes.len));
        const context = observation.context orelse {
            const code = @intFromEnum(windows.GetLastError());
            std.debug.print("Disallowed conformance case={s} context_error={d}\n", .{ @tagName(certificate.name), code });
            if (index < 3 or index == 8 or index == 9) valid = false;
            continue;
        };
        observation.signature = property(context, 15);
        observation.key = property(context, 25);
        observation.direct_tbs = nativeTbs(certificate.bytes);
        const signature = observation.signature;
        const key = observation.key;
        const direct = observation.direct_tbs;
        std.debug.print("Disallowed conformance case={s} property15={s}/{d}/{d} native_tbs={s}/{d}/{d} equal15={} md5={any} sha1={any} sha256={any} sha384={any} sha512={any}\n", .{
            @tagName(certificate.name),                       @tagName(signature.state),                      signature.code,                                   signature.length,
            @tagName(direct.state),                           direct.code,                                    direct.length,                                    signature.equal(direct),
            matches(signature, certificate.domains, .md5),    matches(signature, certificate.domains, .sha1), matches(signature, certificate.domains, .sha256), matches(signature, certificate.domains, .sha384),
            matches(signature, certificate.domains, .sha512),
        });
        std.debug.print("Disallowed conformance case={s} property25={s}/{d}/{d} md5={any}\n", .{
            @tagName(certificate.name), @tagName(key.state), key.code, key.length, matches(key, certificate.domains, .md5),
        });
        if (index < 3 or index == 8 or index == 9) {
            const expected: ReferenceHash = if (index == 2 or index == 9) .sha384 else .sha256;
            valid = valid and signature.equal(reference(expected, certificate.domains[1])) and signature.equal(direct) and key.state == .present;
        }
    }
    const same_key = observations[0].key.equal(observations[1].key);
    const different_tbs = !observations[0].signature.equal(observations[1].signature);
    std.debug.print("Disallowed conformance same_key_pair property25_equal={} property15_different={}\n", .{ same_key, different_tbs });
    valid = valid and same_key and different_tbs;
    const rsa_same_key = observations[8].key.equal(observations[9].key);
    const rsa_different_tbs = !observations[8].signature.equal(observations[9].signature);
    std.debug.print("Disallowed conformance rsa_same_key_pair property25_equal={} property15_different={}\n", .{ rsa_same_key, rsa_different_tbs });
    valid = valid and rsa_same_key and rsa_different_tbs;
    const lookups_valid = try lookupMatrix(arena.allocator(), &certs, &observations);
    std.debug.print("Disallowed conformance batch_complete=true documented_controls_passed={} generic_lookup_only=true\n", .{valid and lookups_valid});
    try std.testing.expect(valid and lookups_valid);
}
