//! Documented Disallowed deny identities, not Windows chain verification.
//! Property 15 hashes exact TBS DER according to its signature algorithm;
//! property 25 hashes the raw subjectPublicKey BIT STRING payload with MD5.
const std = @import("std");
const x509 = @import("x509_policy.zig");
const certificate_crypto = @import("cert_crypto.zig");
const algorithms = @import("crypto/algorithm_encoding.zig");
const crypto = @import("crypto/provider.zig");
const signature = @import("cert_signature.zig");
const Error = @import("trust.zig").TrustError;

pub const Inputs = struct {
    tbs_der: []const u8,
    public_key_bits: []const u8,
    signature_hash: crypto.HashAlgorithm,
};

pub fn parse(bytes: []const u8) Error!Inputs {
    // This independently checks the identical inner/outer AlgorithmIdentifiers,
    // complete certificate DER and key framing even outside the path validator.
    const certificate = try x509.parse(bytes);
    if (certificate.weak_key) return error.TlsTrustStoreLoadFailed;
    const key = certificate_crypto.parsePublicKeyInfo(certificate.spki) catch
        return error.TlsTrustStoreLoadFailed;
    return .{
        .tbs_der = certificate.tbs,
        .public_key_bits = key.key.bytes,
        .signature_hash = try signatureHash(certificate.algorithm),
    };
}

fn signatureHash(algorithm: signature.AlgorithmIdentifier) Error!crypto.HashAlgorithm {
    const rsa = [_]struct { oid: []const u8, hash: crypto.HashAlgorithm }{
        .{ .oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04", .hash = .md5 },
        .{ .oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05", .hash = .sha1 },
        .{ .oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", .hash = .sha256 },
        .{ .oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c", .hash = .sha384 },
        .{ .oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d", .hash = .sha512 },
    };
    for (rsa) |mapping| {
        if (std.mem.eql(u8, algorithm.oid, mapping.oid)) {
            if (algorithm.parameters_der) |parameters| {
                if (!std.mem.eql(u8, parameters, "\x05\x00")) return error.TlsTrustStoreLoadFailed;
            } else if (mapping.hash == .md5 or mapping.hash == .sha1) return error.TlsTrustStoreLoadFailed;
            return mapping.hash;
        }
    }
    if (std.mem.eql(u8, algorithm.oid, "\x2a\x86\x48\xce\x3d\x04\x03\x02") or
        std.mem.eql(u8, algorithm.oid, "\x2a\x86\x48\xce\x3d\x04\x03\x03"))
    {
        if (algorithm.parameters_der != null) return error.TlsTrustStoreLoadFailed;
        return if (algorithm.oid[algorithm.oid.len - 1] == 2) .sha256 else .sha384;
    }
    if (std.mem.eql(u8, algorithm.oid, algorithms.pss_oid)) {
        const parameters = algorithm.parameters_der orelse return error.TlsTrustStoreLoadFailed;
        if (std.mem.eql(u8, parameters, "\x30\x00")) return .sha1;
        const parsed = algorithms.parsePss(parameters) catch return error.TlsTrustStoreLoadFailed;
        if (parsed.hash == .sha1 or parsed.hash == .md5 or parsed.hash != parsed.mgf_hash or
            parsed.salt_length != parsed.hash.digestLength() or parsed.trailer != 1)
            return error.TlsTrustStoreLoadFailed;
        // The supported SHA-2 profile has explicit hash, MGF1 and salt fields;
        // the default trailer must be omitted. Other encodings stay closed.
        var outer = x509.Reader.init(parameters);
        var fields = x509.Reader.init((try outer.take(0x30)).content);
        try outer.finish();
        for ([_]u8{ 0xa0, 0xa1, 0xa2 }) |tag| _ = try fields.take(tag);
        fields.finish() catch return error.TlsTrustStoreLoadFailed;
        return parsed.hash;
    }
    // Ed25519 has no supported P15 hash mapping. A successful P25 calculation
    // cannot turn unavailable P15 policy into an unchecked nonmatch.
    return error.TlsTrustStoreLoadFailed;
}
