const p = @import("provider.zig");

// ABI 1 data layout, independent of the current declarations.
const LegacyCapabilities = struct {
    random: bool = false,
    hashes: u8 = 0,
    hmac_hashes: u8 = 0,
    hkdf_hashes: u8 = 0,
    tls12_prf_hashes: u8 = 0,
    aeads: u8 = 0,
    key_agreements: u8 = 0,
    kems: u8 = 0,
    signature_sign: u16 = 0,
    signature_verify: u16 = 0,
    constant_time_equal: bool = false,
};

fn require(comptime condition: bool, comptime message: []const u8) void {
    if (!condition) @compileError(message);
}

test "ABI2 retains ABI1 byte layouts offsets and legacy enum tags" {
    comptime {
        require(@sizeOf(p.HashAlgorithm) == 1, "hash tag width changed");
        for (.{ p.HashAlgorithm.sha1, p.HashAlgorithm.sha256, p.HashAlgorithm.sha384, p.HashAlgorithm.sha512, p.HashAlgorithm.md5 }, 0..) |algorithm, tag|
            require(@intFromEnum(algorithm) == tag, "hash tag changed");
        const pointer_size = @sizeOf(*anyopaque);
        require(@sizeOf(p.CryptoProvider) == 3 * pointer_size, "provider descriptor size changed");
        require(@alignOf(p.CryptoProvider) == @alignOf(*anyopaque), "provider descriptor alignment changed");
        require(@offsetOf(p.CryptoProvider, "abi_version") == 0, "ABI field moved");
        require(@offsetOf(p.CryptoProvider, "context") == pointer_size, "context field moved");
        require(@offsetOf(p.CryptoProvider, "vtable") == 2 * pointer_size, "vtable field moved");
        require(@sizeOf(p.Capabilities) == @sizeOf(LegacyCapabilities), "capability size changed");
        require(@alignOf(p.Capabilities) == @alignOf(LegacyCapabilities), "capability alignment changed");
        const fields = @typeInfo(p.Capabilities).@"struct".fields;
        const old_fields = @typeInfo(LegacyCapabilities).@"struct".fields;
        require(fields.len == old_fields.len, "capability field count changed");
        for (old_fields, fields) |old, field| {
            require(old.type == field.type, "capability field type changed");
            require(@offsetOf(p.Capabilities, old.name) == @offsetOf(LegacyCapabilities, old.name), "capability field moved");
        }
        const names = .{
            "capabilities",          "random",            "hashCreate",          "hashUpdate",        "hashSnapshot", "hashClone",         "hashDestroy",
            "hmac",                  "hkdfExtract",       "hkdfExpand",          "tls12Prf",          "aeadSeal",     "aeadOpen",          "keyAgreementGenerate",
            "keyAgreementPublicKey", "keyAgreementAgree", "keyAgreementDestroy", "kemGenerate",       "kemPublicKey", "kemEncapsulate",    "kemDecapsulate",
            "kemDestroy",            "signingKeyImport",  "sign",                "signingKeyDestroy", "verify",       "constantTimeEqual",
        };
        require(@typeInfo(p.VTable).@"struct".fields.len == names.len, "vtable slot count changed");
        require(@sizeOf(p.VTable) == names.len * pointer_size, "vtable size changed");
        require(@alignOf(p.VTable) == @alignOf(*anyopaque), "vtable alignment changed");
        for (names, 0..) |name, index|
            require(@offsetOf(p.VTable, name) == index * pointer_size, "vtable slot moved");
    }
}
