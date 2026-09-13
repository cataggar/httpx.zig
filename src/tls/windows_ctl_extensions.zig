//! CTL-wide extensions. A CT log catalog is not certificate-path authority:
//! validate its supported framing, but never install or use its log keys.
const std = @import("std");
const x509 = @import("x509_policy.zig");
const cert_crypto = @import("cert_crypto.zig");
const Error = @import("trust.zig").TrustError;
const Reader = x509.Reader;

pub const cert_log_list_oid = "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x34";
pub const max_log_keys = 256;
pub const max_log_key_bytes = 4096;

pub fn validate(bytes: []const u8, value_limit: usize) Error!void {
    validateInner(bytes, value_limit) catch return error.TlsTrustStoreLoadFailed;
}

fn validateInner(bytes: []const u8, value_limit: usize) Error!void {
    var outer = Reader.init(bytes);
    var wrapper = Reader.init((try outer.take(0xa0)).content);
    try outer.finish();
    var extensions = Reader.init((try wrapper.take(0x30)).content);
    try wrapper.finish();
    var seen_catalog = false;
    while (extensions.peek() != null) {
        var extension = Reader.init((try extensions.take(0x30)).content);
        const oid = (try extension.take(0x06)).content;
        // The only supported extension is noncritical, with the DER DEFAULT
        // FALSE omitted. Unknown, critical, duplicate, and noncanonical forms
        // cannot become a blanket "ignore noncritical" policy.
        if (!std.mem.eql(u8, oid, cert_log_list_oid) or seen_catalog or extension.peek() == 0x01)
            return error.TlsTrustStoreLoadFailed;
        const catalog = (try extension.take(0x04)).content;
        try extension.finish();
        if (catalog.len == 0 or catalog.len > value_limit) return error.TlsTrustStoreLoadFailed;
        try validateCatalog(catalog);
        seen_catalog = true;
    }
    if (!seen_catalog) return error.TlsTrustStoreLoadFailed;
}

fn validateCatalog(bytes: []const u8) Error!void {
    var outer = Reader.init(bytes);
    var catalog = Reader.init((try outer.take(0x30)).content);
    try outer.finish();
    var header = Reader.init((try catalog.take(0x30)).content);
    // These three format parameters have no authorization meaning here.
    // Do not turn them into permissions, dates, policy flags, or CT support.
    for (0..3) |_| {
        const integer = (try header.take(0x02)).content;
        if (integer.len == 0 or integer.len > 5 or integer[0] & 0x80 != 0 or
            (integer.len > 1 and integer[0] == 0 and integer[1] & 0x80 == 0) or
            (integer.len == 5 and integer[0] != 0))
            return error.TlsTrustStoreLoadFailed;
    }
    try header.finish();
    var count: usize = 0;
    while (catalog.peek() != null) {
        if (count == max_log_keys) return error.TlsTrustStoreLoadFailed;
        count += 1;
        const spki = try catalog.take(0x30);
        if (spki.encoded.len > max_log_key_bytes) return error.TlsTrustStoreLoadFailed;
        const key = cert_crypto.parsePublicKeyInfo(spki.encoded) catch return error.TlsTrustStoreLoadFailed;
        switch (key.key.algorithm) {
            .rsa, .ecdsa_p256, .ecdsa_p384 => {},
            else => return error.TlsTrustStoreLoadFailed,
        }
    }
}
