//! Provider-neutral cryptographic contract for the httpx TLS engine.
//!
//! `CryptoProvider` is a borrowed descriptor. Its context and vtable must
//! outlive every configuration, handshake, session, connection, and owned
//! handle that refers to it. Copying the descriptor never transfers context
//! ownership.
//!
//! Every callback is synchronous. Input and output slices are borrowed only
//! for the duration of a callback, except that signing-key import must copy
//! the supplied key into provider-owned storage. A context shared by multiple
//! TLS connections must be thread-safe. Individual mutable handles are
//! single-owner and single-threaded.
//!
//! Provider-created handles are opaque and allocated with the supplied
//! allocator. Creation callbacks publish handles through an optional out
//! parameter; once published, even a callback that subsequently fails must
//! leave the handle safe for the matching destroy callback. The wrappers
//! below clean up such partial construction and invoke exactly one destroy
//! callback after normal `take`/`deinit` use. Destroy callbacks must wipe
//! provider-owned secrets before releasing storage.
//!
//! Zig cannot prohibit bitwise copying of an owning struct. Callers must keep
//! handle wrappers at stable addresses, pass pointers to them, and transfer
//! ownership only with `take`. A copied active wrapper aliases the same raw
//! handle and is invalid ownership.
//!
//! Unsupported operations and algorithms are always reported explicitly.
//! This abstraction never falls back to another provider.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const secure_wipe = @import("secure_wipe.zig");
pub const secureWipe = secure_wipe.bytes;
pub const secureWipeValue = secure_wipe.value;

/// Increment for every incompatible vtable or semantic contract change.
pub const current_abi_version: u32 = 1;

pub const HashAlgorithm = enum(u8) {
    sha1,
    sha256,
    sha384,
    sha512,

    pub fn digestLength(self: HashAlgorithm) usize {
        return switch (self) {
            .sha1 => 20,
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }

    pub fn blockLength(self: HashAlgorithm) usize {
        return switch (self) {
            .sha1, .sha256 => 64,
            .sha384, .sha512 => 128,
        };
    }
};

pub const AeadAlgorithm = enum(u8) {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    pub const nonce_length: usize = 12;
    pub const tag_length: usize = 16;

    pub fn keyLength(self: AeadAlgorithm) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
    }
};

pub const KeyAgreementPublicKeyEncoding = enum(u8) {
    /// RFC 7748 32-byte X25519 u-coordinate.
    x25519_raw,
    /// ANSI X9.62 uncompressed point: 0x04 || X || Y.
    sec1_uncompressed,
};

pub const KeyAgreementAlgorithm = enum(u16) {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    x25519 = 0x001d,

    pub fn publicKeyLength(self: KeyAgreementAlgorithm) usize {
        return switch (self) {
            .x25519 => 32,
            .secp256r1 => 65,
            .secp384r1 => 97,
        };
    }

    pub fn sharedSecretLength(self: KeyAgreementAlgorithm) usize {
        return switch (self) {
            .x25519, .secp256r1 => 32,
            .secp384r1 => 48,
        };
    }

    pub fn publicKeyEncoding(self: KeyAgreementAlgorithm) KeyAgreementPublicKeyEncoding {
        return switch (self) {
            .x25519 => .x25519_raw,
            .secp256r1, .secp384r1 => .sec1_uncompressed,
        };
    }
};

pub const KemAlgorithm = enum(u8) {
    ml_kem_768,

    pub fn encapsulationKeyLength(_: KemAlgorithm) usize {
        return 1184;
    }

    pub fn ciphertextLength(_: KemAlgorithm) usize {
        return 1088;
    }

    pub fn sharedSecretLength(_: KemAlgorithm) usize {
        return 32;
    }
};

/// TLS SignatureScheme wire values supported by the provider contract.
pub const SignatureScheme = enum(u16) {
    rsa_pkcs1_sha1 = 0x0201,
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    pub fn hashAlgorithm(self: SignatureScheme) ?HashAlgorithm {
        return switch (self) {
            .rsa_pkcs1_sha1 => .sha1,
            .rsa_pkcs1_sha256,
            .ecdsa_secp256r1_sha256,
            .rsa_pss_rsae_sha256,
            .rsa_pss_pss_sha256,
            => .sha256,
            .rsa_pkcs1_sha384,
            .ecdsa_secp384r1_sha384,
            .rsa_pss_rsae_sha384,
            .rsa_pss_pss_sha384,
            => .sha384,
            .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha512,
            .rsa_pss_pss_sha512,
            => .sha512,
            .ed25519 => null,
        };
    }

    pub fn keyAlgorithm(self: SignatureScheme) SignatureKeyAlgorithm {
        return switch (self) {
            .ecdsa_secp256r1_sha256 => .ecdsa_p256,
            .ecdsa_secp384r1_sha384 => .ecdsa_p384,
            .rsa_pkcs1_sha1,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => .rsa,
            .rsa_pss_pss_sha256,
            .rsa_pss_pss_sha384,
            .rsa_pss_pss_sha512,
            => .rsa_pss,
            .ed25519 => .ed25519,
        };
    }

    pub fn signatureEncoding(self: SignatureScheme) SignatureEncoding {
        return switch (self) {
            .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 => .ecdsa_der,
            .rsa_pkcs1_sha1,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            .rsa_pss_pss_sha256,
            .rsa_pss_pss_sha384,
            .rsa_pss_pss_sha512,
            => .rsa_raw,
            .ed25519 => .ed25519_raw,
        };
    }

    /// Fixed signature size, or `null` for variable-size DER ECDSA and
    /// modulus-sized RSA signatures.
    pub fn fixedSignatureLength(self: SignatureScheme) ?usize {
        return switch (self.signatureEncoding()) {
            .ed25519_raw => 64,
            .ecdsa_der, .rsa_raw => null,
        };
    }

    /// Required output capacity for ECDSA and Ed25519 signatures.
    /// RSA capacity is the imported key's modulus length and is provider-known.
    pub fn signatureCapacity(self: SignatureScheme) ?usize {
        return switch (self) {
            .ecdsa_secp256r1_sha256 => 72,
            .ecdsa_secp384r1_sha384 => 104,
            .ed25519 => 64,
            else => null,
        };
    }
};

pub const SignatureKeyAlgorithm = enum(u8) {
    ecdsa_p256,
    ecdsa_p384,
    /// RSA key carried under the rsaEncryption algorithm identifier.
    rsa,
    /// RSA key restricted by an RSASSA-PSS algorithm identifier.
    rsa_pss,
    ed25519,
};

pub const PublicKeyEncoding = enum(u8) {
    /// Uncompressed SEC1 point. P-256 is 65 bytes; P-384 is 97 bytes.
    sec1_uncompressed,
    /// DER RSAPublicKey (PKCS #1); signature length equals the modulus length.
    rsa_pkcs1_der,
    /// Raw 32-byte Ed25519 public key.
    ed25519_raw,
};

pub const PrivateKeyEncoding = enum(u8) {
    pkcs8_der,
    sec1_der,
    rsa_pkcs1_der,
    /// P-256/P-384 scalar or 32-byte Ed25519 seed.
    raw_secret,
};

pub const SignatureEncoding = enum(u8) {
    /// ASN.1 DER ECDSA-Sig-Value sequence containing `(r, s)`.
    ecdsa_der,
    /// Big-endian RSA signature integer, exactly the modulus length.
    rsa_raw,
    /// Raw 64-byte Ed25519 signature.
    ed25519_raw,
};

pub const PublicKey = struct {
    algorithm: SignatureKeyAlgorithm,
    encoding: PublicKeyEncoding,
    bytes: []const u8,
};

pub const PrivateKey = struct {
    algorithm: SignatureKeyAlgorithm,
    encoding: PrivateKeyEncoding,
    bytes: []const u8,
};

pub const Operation = enum(u8) {
    capabilities,
    random,
    hash_create,
    hash_update,
    hash_snapshot,
    hash_clone,
    hash_destroy,
    hmac,
    hkdf_extract,
    hkdf_expand,
    tls12_prf,
    aead_seal,
    aead_open,
    key_agreement_generate,
    key_agreement_public_key,
    key_agreement_agree,
    key_agreement_destroy,
    kem_generate,
    kem_public_key,
    kem_encapsulate,
    kem_decapsulate,
    kem_destroy,
    signing_key_import,
    sign,
    signing_key_destroy,
    verify,
    constant_time_equal,
};

pub const ErrorCategory = enum(u8) {
    abi,
    unsupported,
    invalid_input,
    allocation,
    entropy,
    authentication,
    key_exchange,
    kem,
    signature,
    internal,
};

pub const ProviderError = error{
    IncompatibleAbiVersion,
    UnsupportedOperation,
    UnsupportedAlgorithm,
    InvalidHandle,
    InvalidInput,
    InvalidOutputLength,
    InvalidDigestLength,
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidTagLength,
    InvalidPublicKeyLength,
    InvalidCiphertextLength,
    InvalidSharedSecretLength,
    InvalidSignatureLength,
    InvalidEncoding,
    InvalidOverlap,
    OutputTooSmall,
    AuthenticationFailed,
    SignatureInvalid,
    EntropyUnavailable,
    KeyGenerationFailed,
    KeyAgreementFailed,
    EncapsulationFailed,
    DecapsulationFailed,
    SigningFailed,
    VerificationFailed,
    OutOfMemory,
    InternalError,
};

pub fn errorCategory(err: ProviderError) ErrorCategory {
    return switch (err) {
        error.IncompatibleAbiVersion => .abi,
        error.UnsupportedOperation, error.UnsupportedAlgorithm => .unsupported,
        error.InvalidHandle,
        error.InvalidInput,
        error.InvalidOutputLength,
        error.InvalidDigestLength,
        error.InvalidKeyLength,
        error.InvalidNonceLength,
        error.InvalidTagLength,
        error.InvalidPublicKeyLength,
        error.InvalidCiphertextLength,
        error.InvalidSharedSecretLength,
        error.InvalidSignatureLength,
        error.InvalidEncoding,
        error.InvalidOverlap,
        error.OutputTooSmall,
        => .invalid_input,
        error.OutOfMemory => .allocation,
        error.EntropyUnavailable => .entropy,
        error.AuthenticationFailed => .authentication,
        error.KeyGenerationFailed, error.KeyAgreementFailed => .key_exchange,
        error.EncapsulationFailed, error.DecapsulationFailed => .kem,
        error.SignatureInvalid,
        error.SigningFailed,
        error.VerificationFailed,
        => .signature,
        error.InternalError => .internal,
    };
}

pub const Capabilities = struct {
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

    pub fn all() Capabilities {
        return .{
            .random = true,
            .hashes = 0x0f,
            .hmac_hashes = 0x0f,
            .hkdf_hashes = 0x0f,
            .tls12_prf_hashes = 0x0f,
            .aeads = 0x07,
            .key_agreements = 0x07,
            .kems = 0x01,
            .signature_sign = 0x1fff,
            .signature_verify = 0x1fff,
            .constant_time_equal = true,
        };
    }

    pub fn supportsHash(self: Capabilities, algorithm: HashAlgorithm) bool {
        return self.hashes & hashBit(algorithm) != 0;
    }

    pub fn setHash(self: *Capabilities, algorithm: HashAlgorithm, supported: bool) void {
        setCapabilityBit(u8, &self.hashes, hashBit(algorithm), supported);
    }

    pub fn supportsHmac(self: Capabilities, algorithm: HashAlgorithm) bool {
        return self.hmac_hashes & hashBit(algorithm) != 0;
    }

    pub fn setHmac(self: *Capabilities, algorithm: HashAlgorithm, supported: bool) void {
        setCapabilityBit(u8, &self.hmac_hashes, hashBit(algorithm), supported);
    }

    pub fn supportsHkdf(self: Capabilities, algorithm: HashAlgorithm) bool {
        return self.hkdf_hashes & hashBit(algorithm) != 0;
    }

    pub fn setHkdf(self: *Capabilities, algorithm: HashAlgorithm, supported: bool) void {
        setCapabilityBit(u8, &self.hkdf_hashes, hashBit(algorithm), supported);
    }

    pub fn supportsTls12Prf(self: Capabilities, algorithm: HashAlgorithm) bool {
        return self.tls12_prf_hashes & hashBit(algorithm) != 0;
    }

    pub fn setTls12Prf(self: *Capabilities, algorithm: HashAlgorithm, supported: bool) void {
        setCapabilityBit(u8, &self.tls12_prf_hashes, hashBit(algorithm), supported);
    }

    pub fn supportsAead(self: Capabilities, algorithm: AeadAlgorithm) bool {
        return self.aeads & aeadBit(algorithm) != 0;
    }

    pub fn setAead(self: *Capabilities, algorithm: AeadAlgorithm, supported: bool) void {
        setCapabilityBit(u8, &self.aeads, aeadBit(algorithm), supported);
    }

    pub fn supportsKeyAgreement(self: Capabilities, algorithm: KeyAgreementAlgorithm) bool {
        return self.key_agreements & keyAgreementBit(algorithm) != 0;
    }

    pub fn setKeyAgreement(self: *Capabilities, algorithm: KeyAgreementAlgorithm, supported: bool) void {
        setCapabilityBit(u8, &self.key_agreements, keyAgreementBit(algorithm), supported);
    }

    pub fn supportsKem(self: Capabilities, algorithm: KemAlgorithm) bool {
        return self.kems & kemBit(algorithm) != 0;
    }

    pub fn setKem(self: *Capabilities, algorithm: KemAlgorithm, supported: bool) void {
        setCapabilityBit(u8, &self.kems, kemBit(algorithm), supported);
    }

    pub fn supportsSign(self: Capabilities, scheme: SignatureScheme) bool {
        return self.signature_sign & signatureBit(scheme) != 0;
    }

    pub fn setSign(self: *Capabilities, scheme: SignatureScheme, supported: bool) void {
        setCapabilityBit(u16, &self.signature_sign, signatureBit(scheme), supported);
    }

    pub fn supportsVerify(self: Capabilities, scheme: SignatureScheme) bool {
        return self.signature_verify & signatureBit(scheme) != 0;
    }

    pub fn setVerify(self: *Capabilities, scheme: SignatureScheme, supported: bool) void {
        setCapabilityBit(u16, &self.signature_verify, signatureBit(scheme), supported);
    }

    pub fn supportsSigningKey(self: Capabilities, algorithm: SignatureKeyAlgorithm) bool {
        const compatible_mask: u16 = switch (algorithm) {
            .ecdsa_p256 => signatureBit(.ecdsa_secp256r1_sha256),
            .ecdsa_p384 => signatureBit(.ecdsa_secp384r1_sha384),
            .rsa => signatureBit(.rsa_pkcs1_sha1) |
                signatureBit(.rsa_pkcs1_sha256) |
                signatureBit(.rsa_pkcs1_sha384) |
                signatureBit(.rsa_pkcs1_sha512) |
                signatureBit(.rsa_pss_rsae_sha256) |
                signatureBit(.rsa_pss_rsae_sha384) |
                signatureBit(.rsa_pss_rsae_sha512),
            .rsa_pss => signatureBit(.rsa_pss_pss_sha256) |
                signatureBit(.rsa_pss_pss_sha384) |
                signatureBit(.rsa_pss_pss_sha512),
            .ed25519 => signatureBit(.ed25519),
        };
        return self.signature_sign & compatible_mask != 0;
    }
};

fn setCapabilityBit(comptime T: type, mask: *T, bit: T, supported: bool) void {
    if (supported) {
        mask.* |= bit;
    } else {
        mask.* &= ~bit;
    }
}

fn hashBit(algorithm: HashAlgorithm) u8 {
    return @as(u8, 1) << @as(u3, @intCast(@intFromEnum(algorithm)));
}

fn aeadBit(algorithm: AeadAlgorithm) u8 {
    return @as(u8, 1) << @as(u3, @intCast(@intFromEnum(algorithm)));
}

fn keyAgreementBit(algorithm: KeyAgreementAlgorithm) u8 {
    const bit_index: u3 = switch (algorithm) {
        .x25519 => 0,
        .secp256r1 => 1,
        .secp384r1 => 2,
    };
    return @as(u8, 1) << bit_index;
}

fn kemBit(algorithm: KemAlgorithm) u8 {
    return @as(u8, 1) << @as(u3, @intCast(@intFromEnum(algorithm)));
}

fn signatureBit(scheme: SignatureScheme) u16 {
    const bit_index: u4 = switch (scheme) {
        .ecdsa_secp256r1_sha256 => 0,
        .ecdsa_secp384r1_sha384 => 1,
        .rsa_pkcs1_sha1 => 2,
        .rsa_pkcs1_sha256 => 3,
        .rsa_pkcs1_sha384 => 4,
        .rsa_pkcs1_sha512 => 5,
        .rsa_pss_rsae_sha256 => 6,
        .rsa_pss_rsae_sha384 => 7,
        .rsa_pss_rsae_sha512 => 8,
        .rsa_pss_pss_sha256 => 9,
        .rsa_pss_pss_sha384 => 10,
        .rsa_pss_pss_sha512 => 11,
        .ed25519 => 12,
    };
    return @as(u16, 1) << bit_index;
}

/// Every field is required. Unsupported callbacks return
/// `UnsupportedOperation` or `UnsupportedAlgorithm`; fields are never null.
pub const VTable = struct {
    capabilities: *const fn (context: *anyopaque) Capabilities,
    random: *const fn (context: *anyopaque, out: []u8) ProviderError!void,

    hashCreate: *const fn (
        context: *anyopaque,
        allocator: Allocator,
        algorithm: HashAlgorithm,
        out_handle: *?*anyopaque,
    ) ProviderError!void,
    hashUpdate: *const fn (context: *anyopaque, handle: *anyopaque, data: []const u8) ProviderError!void,
    /// Writes the current digest without consuming or mutating the handle.
    hashSnapshot: *const fn (context: *anyopaque, handle: *anyopaque, out: []u8) ProviderError!void,
    /// Creates the only permitted duplicate of mutable hash state.
    hashClone: *const fn (
        context: *anyopaque,
        handle: *anyopaque,
        allocator: Allocator,
        out_handle: *?*anyopaque,
    ) ProviderError!void,
    hashDestroy: *const fn (context: *anyopaque, allocator: Allocator, handle: *anyopaque) void,

    hmac: *const fn (
        context: *anyopaque,
        algorithm: HashAlgorithm,
        key: []const u8,
        parts: []const []const u8,
        out: []u8,
    ) ProviderError!void,
    hkdfExtract: *const fn (
        context: *anyopaque,
        algorithm: HashAlgorithm,
        salt: []const u8,
        ikm_parts: []const []const u8,
        out_prk: []u8,
    ) ProviderError!void,
    hkdfExpand: *const fn (
        context: *anyopaque,
        algorithm: HashAlgorithm,
        prk: []const u8,
        info_parts: []const []const u8,
        out: []u8,
    ) ProviderError!void,
    tls12Prf: *const fn (
        context: *anyopaque,
        algorithm: HashAlgorithm,
        secret: []const u8,
        label: []const u8,
        seed_parts: []const []const u8,
        out: []u8,
    ) ProviderError!void,

    /// Supports only disjoint input/output or exact in-place payload buffers.
    /// Tag storage is detached and disjoint. Any callback error after
    /// preflight is an operational error and the wrapper wipes both outputs.
    aeadSeal: *const fn (
        context: *anyopaque,
        algorithm: AeadAlgorithm,
        key: []const u8,
        nonce: []const u8,
        aad_parts: []const []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: []u8,
    ) ProviderError!void,
    /// Tag mismatch must return only `AuthenticationFailed`. The wrapper
    /// securely zeros the complete plaintext destination on every callback
    /// error, including exact in-place operation.
    aeadOpen: *const fn (
        context: *anyopaque,
        algorithm: AeadAlgorithm,
        key: []const u8,
        nonce: []const u8,
        aad_parts: []const []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext: []u8,
    ) ProviderError!void,

    keyAgreementGenerate: *const fn (
        context: *anyopaque,
        allocator: Allocator,
        algorithm: KeyAgreementAlgorithm,
        out_handle: *?*anyopaque,
    ) ProviderError!void,
    keyAgreementPublicKey: *const fn (
        context: *anyopaque,
        handle: *anyopaque,
        out: []u8,
    ) ProviderError!void,
    /// Must validate peer points and reject an all-zero X25519 secret.
    keyAgreementAgree: *const fn (
        context: *anyopaque,
        handle: *anyopaque,
        peer_public_key: []const u8,
        out_shared_secret: []u8,
    ) ProviderError!void,
    keyAgreementDestroy: *const fn (context: *anyopaque, allocator: Allocator, handle: *anyopaque) void,

    kemGenerate: *const fn (
        context: *anyopaque,
        allocator: Allocator,
        algorithm: KemAlgorithm,
        out_handle: *?*anyopaque,
    ) ProviderError!void,
    kemPublicKey: *const fn (context: *anyopaque, handle: *anyopaque, out: []u8) ProviderError!void,
    kemEncapsulate: *const fn (
        context: *anyopaque,
        algorithm: KemAlgorithm,
        encapsulation_key: []const u8,
        out_ciphertext: []u8,
        out_shared_secret: []u8,
    ) ProviderError!void,
    kemDecapsulate: *const fn (
        context: *anyopaque,
        handle: *anyopaque,
        ciphertext: []const u8,
        out_shared_secret: []u8,
    ) ProviderError!void,
    kemDestroy: *const fn (context: *anyopaque, allocator: Allocator, handle: *anyopaque) void,

    signingKeyImport: *const fn (
        context: *anyopaque,
        allocator: Allocator,
        key: PrivateKey,
        out_handle: *?*anyopaque,
    ) ProviderError!void,
    /// ECDSA signatures are DER, RSA signatures are modulus-sized raw
    /// integers, and Ed25519 signatures are 64 raw bytes.
    sign: *const fn (
        context: *anyopaque,
        handle: *anyopaque,
        scheme: SignatureScheme,
        message_parts: []const []const u8,
        out_signature: []u8,
    ) ProviderError!usize,
    signingKeyDestroy: *const fn (context: *anyopaque, allocator: Allocator, handle: *anyopaque) void,
    /// Primitive verification only. Certificate parsing, trust, hostname,
    /// validity, and chain policy belong to TrustProvider.
    verify: *const fn (
        context: *anyopaque,
        scheme: SignatureScheme,
        public_key: PublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) ProviderError!void,

    constantTimeEqual: *const fn (
        context: *anyopaque,
        a: []const u8,
        b: []const u8,
    ) ProviderError!bool,
};

pub const CryptoProvider = extern struct {
    abi_version: u32,
    context: *anyopaque,
    vtable: *const VTable,

    pub fn init(context: *anyopaque, vtable: *const VTable) CryptoProvider {
        return .{
            .abi_version = current_abi_version,
            .context = context,
            .vtable = vtable,
        };
    }

    pub fn validate(self: CryptoProvider) ProviderError!void {
        if (self.abi_version != current_abi_version) return error.IncompatibleAbiVersion;
    }

    pub fn capabilities(self: CryptoProvider) ProviderError!Capabilities {
        try self.validate();
        return self.vtable.capabilities(self.context);
    }

    pub fn random(self: CryptoProvider, out: []u8) ProviderError!void {
        const caps = try self.capabilities();
        if (!caps.random) return error.UnsupportedOperation;
        self.vtable.random(self.context, out) catch |err| {
            secureWipe(out);
            return err;
        };
    }

    pub fn hashCreate(
        self: CryptoProvider,
        allocator: Allocator,
        algorithm: HashAlgorithm,
    ) ProviderError!HashHandle {
        const caps = try self.capabilities();
        if (!caps.supportsHash(algorithm)) return error.UnsupportedAlgorithm;

        var raw_handle: ?*anyopaque = null;
        errdefer if (raw_handle) |handle| self.vtable.hashDestroy(self.context, allocator, handle);
        try self.vtable.hashCreate(self.context, allocator, algorithm, &raw_handle);
        const handle = raw_handle orelse return error.InternalError;
        return .{
            .provider = self,
            .allocator = allocator,
            .algorithm = algorithm,
            .raw_handle = handle,
        };
    }

    pub fn hmac(
        self: CryptoProvider,
        algorithm: HashAlgorithm,
        key: []const u8,
        parts: []const []const u8,
        out: []u8,
    ) ProviderError!void {
        const caps = try self.capabilities();
        if (!caps.supportsHmac(algorithm)) return error.UnsupportedAlgorithm;
        if (out.len != algorithm.digestLength()) return error.InvalidDigestLength;
        self.vtable.hmac(self.context, algorithm, key, parts, out) catch |err| {
            secureWipe(out);
            return err;
        };
    }

    pub fn hkdfExtract(
        self: CryptoProvider,
        algorithm: HashAlgorithm,
        salt: []const u8,
        ikm_parts: []const []const u8,
        out_prk: []u8,
    ) ProviderError!void {
        const caps = try self.capabilities();
        if (!caps.supportsHkdf(algorithm)) return error.UnsupportedAlgorithm;
        if (out_prk.len != algorithm.digestLength()) return error.InvalidDigestLength;
        self.vtable.hkdfExtract(self.context, algorithm, salt, ikm_parts, out_prk) catch |err| {
            secureWipe(out_prk);
            return err;
        };
    }

    pub fn hkdfExpand(
        self: CryptoProvider,
        algorithm: HashAlgorithm,
        prk: []const u8,
        info_parts: []const []const u8,
        out: []u8,
    ) ProviderError!void {
        const caps = try self.capabilities();
        if (!caps.supportsHkdf(algorithm)) return error.UnsupportedAlgorithm;
        const digest_len = algorithm.digestLength();
        if (prk.len != digest_len) return error.InvalidDigestLength;
        if (out.len > 255 * digest_len) return error.InvalidOutputLength;
        self.vtable.hkdfExpand(self.context, algorithm, prk, info_parts, out) catch |err| {
            secureWipe(out);
            return err;
        };
    }

    pub fn tls12Prf(
        self: CryptoProvider,
        algorithm: HashAlgorithm,
        secret: []const u8,
        label: []const u8,
        seed_parts: []const []const u8,
        out: []u8,
    ) ProviderError!void {
        const caps = try self.capabilities();
        if (!caps.supportsTls12Prf(algorithm)) return error.UnsupportedAlgorithm;
        self.vtable.tls12Prf(self.context, algorithm, secret, label, seed_parts, out) catch |err| {
            secureWipe(out);
            return err;
        };
    }

    pub fn aeadSeal(
        self: CryptoProvider,
        algorithm: AeadAlgorithm,
        key: []const u8,
        nonce: []const u8,
        aad_parts: []const []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: []u8,
    ) ProviderError!void {
        const caps = try self.capabilities();
        if (!caps.supportsAead(algorithm)) return error.UnsupportedAlgorithm;
        try validateAeadSeal(algorithm, key, nonce, aad_parts, plaintext, ciphertext, tag);
        self.vtable.aeadSeal(
            self.context,
            algorithm,
            key,
            nonce,
            aad_parts,
            plaintext,
            ciphertext,
            tag,
        ) catch |err| {
            secureWipe(ciphertext);
            secureWipe(tag);
            return err;
        };
    }

    pub fn aeadOpen(
        self: CryptoProvider,
        algorithm: AeadAlgorithm,
        key: []const u8,
        nonce: []const u8,
        aad_parts: []const []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext: []u8,
    ) ProviderError!void {
        const caps = try self.capabilities();
        if (!caps.supportsAead(algorithm)) return error.UnsupportedAlgorithm;
        try validateAeadOpen(algorithm, key, nonce, aad_parts, ciphertext, tag, plaintext);
        self.vtable.aeadOpen(
            self.context,
            algorithm,
            key,
            nonce,
            aad_parts,
            ciphertext,
            tag,
            plaintext,
        ) catch |err| {
            secureWipe(plaintext);
            return err;
        };
    }

    pub fn keyAgreementGenerate(
        self: CryptoProvider,
        allocator: Allocator,
        algorithm: KeyAgreementAlgorithm,
    ) ProviderError!KeyAgreementKey {
        const caps = try self.capabilities();
        if (!caps.supportsKeyAgreement(algorithm)) return error.UnsupportedAlgorithm;

        var raw_handle: ?*anyopaque = null;
        errdefer if (raw_handle) |handle| self.vtable.keyAgreementDestroy(self.context, allocator, handle);
        try self.vtable.keyAgreementGenerate(self.context, allocator, algorithm, &raw_handle);
        const handle = raw_handle orelse return error.InternalError;
        return .{
            .provider = self,
            .allocator = allocator,
            .algorithm = algorithm,
            .raw_handle = handle,
        };
    }

    pub fn kemGenerate(
        self: CryptoProvider,
        allocator: Allocator,
        algorithm: KemAlgorithm,
    ) ProviderError!KemKey {
        const caps = try self.capabilities();
        if (!caps.supportsKem(algorithm)) return error.UnsupportedAlgorithm;

        var raw_handle: ?*anyopaque = null;
        errdefer if (raw_handle) |handle| self.vtable.kemDestroy(self.context, allocator, handle);
        try self.vtable.kemGenerate(self.context, allocator, algorithm, &raw_handle);
        const handle = raw_handle orelse return error.InternalError;
        return .{
            .provider = self,
            .allocator = allocator,
            .algorithm = algorithm,
            .raw_handle = handle,
        };
    }

    pub fn kemEncapsulate(
        self: CryptoProvider,
        algorithm: KemAlgorithm,
        encapsulation_key: []const u8,
        out_ciphertext: []u8,
        out_shared_secret: []u8,
    ) ProviderError!void {
        const caps = try self.capabilities();
        if (!caps.supportsKem(algorithm)) return error.UnsupportedAlgorithm;
        if (encapsulation_key.len != algorithm.encapsulationKeyLength()) return error.InvalidPublicKeyLength;
        if (out_ciphertext.len != algorithm.ciphertextLength()) return error.InvalidCiphertextLength;
        if (out_shared_secret.len != algorithm.sharedSecretLength()) return error.InvalidSharedSecretLength;
        if (slicesOverlap(out_ciphertext, out_shared_secret) or
            slicesOverlap(out_ciphertext, encapsulation_key) or
            slicesOverlap(out_shared_secret, encapsulation_key))
        {
            return error.InvalidOverlap;
        }
        self.vtable.kemEncapsulate(
            self.context,
            algorithm,
            encapsulation_key,
            out_ciphertext,
            out_shared_secret,
        ) catch |err| {
            secureWipe(out_ciphertext);
            secureWipe(out_shared_secret);
            return err;
        };
    }

    pub fn signingKeyImport(
        self: CryptoProvider,
        allocator: Allocator,
        key: PrivateKey,
    ) ProviderError!SigningKey {
        const caps = try self.capabilities();
        if (!caps.supportsSigningKey(key.algorithm)) return error.UnsupportedAlgorithm;
        try validatePrivateKey(key);

        var raw_handle: ?*anyopaque = null;
        errdefer if (raw_handle) |handle| self.vtable.signingKeyDestroy(self.context, allocator, handle);
        try self.vtable.signingKeyImport(self.context, allocator, key, &raw_handle);
        const handle = raw_handle orelse return error.InternalError;
        return .{
            .provider = self,
            .allocator = allocator,
            .algorithm = key.algorithm,
            .raw_handle = handle,
        };
    }

    pub fn verify(
        self: CryptoProvider,
        scheme: SignatureScheme,
        public_key: PublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) ProviderError!void {
        const caps = try self.capabilities();
        if (!caps.supportsVerify(scheme)) return error.UnsupportedAlgorithm;
        if (scheme.keyAlgorithm() != public_key.algorithm) return error.UnsupportedAlgorithm;
        try validatePublicKey(public_key);
        try validateSignature(scheme, signature);
        try self.vtable.verify(self.context, scheme, public_key, message_parts, signature);
    }

    pub fn constantTimeEqual(
        self: CryptoProvider,
        a: []const u8,
        b: []const u8,
    ) ProviderError!bool {
        const caps = try self.capabilities();
        if (!caps.constant_time_equal) return error.UnsupportedOperation;
        if (a.len != b.len) return error.InvalidInput;
        return self.vtable.constantTimeEqual(self.context, a, b);
    }
};

pub const HashHandle = struct {
    provider: CryptoProvider,
    allocator: Allocator,
    algorithm: HashAlgorithm,
    raw_handle: ?*anyopaque,

    pub fn isActive(self: *const HashHandle) bool {
        return self.raw_handle != null;
    }

    pub fn update(self: *HashHandle, data: []const u8) ProviderError!void {
        try self.provider.validate();
        const handle = self.raw_handle orelse return error.InvalidHandle;
        try self.provider.vtable.hashUpdate(self.provider.context, handle, data);
    }

    pub fn snapshot(self: *HashHandle, out: []u8) ProviderError!void {
        try self.provider.validate();
        const handle = self.raw_handle orelse return error.InvalidHandle;
        if (out.len != self.algorithm.digestLength()) return error.InvalidDigestLength;
        self.provider.vtable.hashSnapshot(self.provider.context, handle, out) catch |err| {
            secureWipe(out);
            return err;
        };
    }

    pub fn clone(self: *HashHandle, allocator: Allocator) ProviderError!HashHandle {
        try self.provider.validate();
        const handle = self.raw_handle orelse return error.InvalidHandle;
        var cloned_raw: ?*anyopaque = null;
        errdefer if (cloned_raw) |raw| self.provider.vtable.hashDestroy(self.provider.context, allocator, raw);
        try self.provider.vtable.hashClone(self.provider.context, handle, allocator, &cloned_raw);
        const raw = cloned_raw orelse return error.InternalError;
        return .{
            .provider = self.provider,
            .allocator = allocator,
            .algorithm = self.algorithm,
            .raw_handle = raw,
        };
    }

    pub fn take(self: *HashHandle) ProviderError!HashHandle {
        if (self.raw_handle == null) return error.InvalidHandle;
        const moved = self.*;
        self.raw_handle = null;
        return moved;
    }

    pub fn deinit(self: *HashHandle) void {
        const handle = self.raw_handle orelse return;
        self.raw_handle = null;
        self.provider.vtable.hashDestroy(self.provider.context, self.allocator, handle);
    }
};

pub const KeyAgreementKey = struct {
    provider: CryptoProvider,
    allocator: Allocator,
    algorithm: KeyAgreementAlgorithm,
    raw_handle: ?*anyopaque,

    pub fn isActive(self: *const KeyAgreementKey) bool {
        return self.raw_handle != null;
    }

    pub fn publicKey(self: *KeyAgreementKey, out: []u8) ProviderError!void {
        try self.provider.validate();
        const handle = self.raw_handle orelse return error.InvalidHandle;
        if (out.len != self.algorithm.publicKeyLength()) return error.InvalidPublicKeyLength;
        self.provider.vtable.keyAgreementPublicKey(self.provider.context, handle, out) catch |err| {
            secureWipe(out);
            return err;
        };
    }

    pub fn agree(
        self: *KeyAgreementKey,
        peer_public_key: []const u8,
        out_shared_secret: []u8,
    ) ProviderError!void {
        try self.provider.validate();
        const handle = self.raw_handle orelse return error.InvalidHandle;
        if (peer_public_key.len != self.algorithm.publicKeyLength()) return error.InvalidPublicKeyLength;
        if (out_shared_secret.len != self.algorithm.sharedSecretLength()) return error.InvalidSharedSecretLength;
        if (slicesOverlap(peer_public_key, out_shared_secret)) return error.InvalidOverlap;
        self.provider.vtable.keyAgreementAgree(
            self.provider.context,
            handle,
            peer_public_key,
            out_shared_secret,
        ) catch |err| {
            secureWipe(out_shared_secret);
            return err;
        };
    }

    pub fn take(self: *KeyAgreementKey) ProviderError!KeyAgreementKey {
        if (self.raw_handle == null) return error.InvalidHandle;
        const moved = self.*;
        self.raw_handle = null;
        return moved;
    }

    pub fn deinit(self: *KeyAgreementKey) void {
        const handle = self.raw_handle orelse return;
        self.raw_handle = null;
        self.provider.vtable.keyAgreementDestroy(self.provider.context, self.allocator, handle);
    }
};

pub const KemKey = struct {
    provider: CryptoProvider,
    allocator: Allocator,
    algorithm: KemAlgorithm,
    raw_handle: ?*anyopaque,

    pub fn isActive(self: *const KemKey) bool {
        return self.raw_handle != null;
    }

    pub fn publicKey(self: *KemKey, out: []u8) ProviderError!void {
        try self.provider.validate();
        const handle = self.raw_handle orelse return error.InvalidHandle;
        if (out.len != self.algorithm.encapsulationKeyLength()) return error.InvalidPublicKeyLength;
        self.provider.vtable.kemPublicKey(self.provider.context, handle, out) catch |err| {
            secureWipe(out);
            return err;
        };
    }

    pub fn decapsulate(
        self: *KemKey,
        ciphertext: []const u8,
        out_shared_secret: []u8,
    ) ProviderError!void {
        try self.provider.validate();
        const handle = self.raw_handle orelse return error.InvalidHandle;
        if (ciphertext.len != self.algorithm.ciphertextLength()) return error.InvalidCiphertextLength;
        if (out_shared_secret.len != self.algorithm.sharedSecretLength()) return error.InvalidSharedSecretLength;
        if (slicesOverlap(ciphertext, out_shared_secret)) return error.InvalidOverlap;
        self.provider.vtable.kemDecapsulate(
            self.provider.context,
            handle,
            ciphertext,
            out_shared_secret,
        ) catch |err| {
            secureWipe(out_shared_secret);
            return err;
        };
    }

    pub fn take(self: *KemKey) ProviderError!KemKey {
        if (self.raw_handle == null) return error.InvalidHandle;
        const moved = self.*;
        self.raw_handle = null;
        return moved;
    }

    pub fn deinit(self: *KemKey) void {
        const handle = self.raw_handle orelse return;
        self.raw_handle = null;
        self.provider.vtable.kemDestroy(self.provider.context, self.allocator, handle);
    }
};

pub const SigningKey = struct {
    provider: CryptoProvider,
    allocator: Allocator,
    algorithm: SignatureKeyAlgorithm,
    raw_handle: ?*anyopaque,

    pub fn isActive(self: *const SigningKey) bool {
        return self.raw_handle != null;
    }

    pub fn sign(
        self: *SigningKey,
        scheme: SignatureScheme,
        message_parts: []const []const u8,
        out_signature: []u8,
    ) ProviderError![]u8 {
        try self.provider.validate();
        const handle = self.raw_handle orelse return error.InvalidHandle;
        const caps = self.provider.vtable.capabilities(self.provider.context);
        if (!caps.supportsSign(scheme)) return error.UnsupportedAlgorithm;
        if (scheme.keyAlgorithm() != self.algorithm) return error.UnsupportedAlgorithm;
        if (scheme.signatureCapacity()) |required_capacity| {
            if (out_signature.len < required_capacity) return error.OutputTooSmall;
        } else if (out_signature.len == 0) {
            return error.OutputTooSmall;
        }

        const signature_len = self.provider.vtable.sign(
            self.provider.context,
            handle,
            scheme,
            message_parts,
            out_signature,
        ) catch |err| {
            secureWipe(out_signature);
            return err;
        };
        if (signature_len > out_signature.len) {
            secureWipe(out_signature);
            return error.InternalError;
        }
        const signature = out_signature[0..signature_len];
        validateSignature(scheme, signature) catch |err| {
            secureWipe(out_signature);
            return err;
        };
        return signature;
    }

    pub fn take(self: *SigningKey) ProviderError!SigningKey {
        if (self.raw_handle == null) return error.InvalidHandle;
        const moved = self.*;
        self.raw_handle = null;
        return moved;
    }

    pub fn deinit(self: *SigningKey) void {
        const handle = self.raw_handle orelse return;
        self.raw_handle = null;
        self.provider.vtable.signingKeyDestroy(self.provider.context, self.allocator, handle);
    }
};

fn validatePrivateKey(key: PrivateKey) ProviderError!void {
    if (key.bytes.len == 0) return error.InvalidEncoding;
    switch (key.encoding) {
        .pkcs8_der => {},
        .sec1_der => switch (key.algorithm) {
            .ecdsa_p256, .ecdsa_p384 => {},
            else => return error.InvalidEncoding,
        },
        .rsa_pkcs1_der => switch (key.algorithm) {
            .rsa, .rsa_pss => {},
            else => return error.InvalidEncoding,
        },
        .raw_secret => {
            const expected_len: usize = switch (key.algorithm) {
                .ecdsa_p256, .ed25519 => 32,
                .ecdsa_p384 => 48,
                .rsa, .rsa_pss => return error.InvalidEncoding,
            };
            if (key.bytes.len != expected_len) return error.InvalidKeyLength;
        },
    }
}

fn validatePublicKey(key: PublicKey) ProviderError!void {
    const expected_len: ?usize = switch (key.algorithm) {
        .ecdsa_p256 => if (key.encoding == .sec1_uncompressed) 65 else return error.InvalidEncoding,
        .ecdsa_p384 => if (key.encoding == .sec1_uncompressed) 97 else return error.InvalidEncoding,
        .rsa, .rsa_pss => if (key.encoding == .rsa_pkcs1_der) null else return error.InvalidEncoding,
        .ed25519 => if (key.encoding == .ed25519_raw) 32 else return error.InvalidEncoding,
    };
    if (expected_len) |len| {
        if (key.bytes.len != len) return error.InvalidPublicKeyLength;
    } else if (key.bytes.len == 0) {
        return error.InvalidEncoding;
    }
}

fn validateSignature(scheme: SignatureScheme, signature: []const u8) ProviderError!void {
    switch (scheme.signatureEncoding()) {
        .ecdsa_der => {
            const max_len = scheme.signatureCapacity().?;
            if (signature.len < 8 or signature.len > max_len) return error.InvalidSignatureLength;
        },
        .rsa_raw => {
            if (signature.len == 0) return error.InvalidSignatureLength;
        },
        .ed25519_raw => {
            if (signature.len != 64) return error.InvalidSignatureLength;
        },
    }
}

fn validateAeadSeal(
    algorithm: AeadAlgorithm,
    key: []const u8,
    nonce: []const u8,
    aad_parts: []const []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: []u8,
) ProviderError!void {
    if (key.len != algorithm.keyLength()) return error.InvalidKeyLength;
    if (nonce.len != AeadAlgorithm.nonce_length) return error.InvalidNonceLength;
    if (tag.len != AeadAlgorithm.tag_length) return error.InvalidTagLength;
    if (ciphertext.len != plaintext.len) return error.InvalidOutputLength;
    if (slicesOverlap(plaintext, ciphertext) and !sameSlice(plaintext, ciphertext)) return error.InvalidOverlap;
    if (slicesOverlap(tag, plaintext) or slicesOverlap(tag, ciphertext)) return error.InvalidOverlap;
    try validateAeadOutputOverlap(ciphertext, tag, key, nonce, aad_parts);
}

fn validateAeadOpen(
    algorithm: AeadAlgorithm,
    key: []const u8,
    nonce: []const u8,
    aad_parts: []const []const u8,
    ciphertext: []const u8,
    tag: []const u8,
    plaintext: []u8,
) ProviderError!void {
    if (key.len != algorithm.keyLength()) return error.InvalidKeyLength;
    if (nonce.len != AeadAlgorithm.nonce_length) return error.InvalidNonceLength;
    if (tag.len != AeadAlgorithm.tag_length) return error.InvalidTagLength;
    if (plaintext.len != ciphertext.len) return error.InvalidOutputLength;
    if (slicesOverlap(ciphertext, plaintext) and !sameSlice(ciphertext, plaintext)) return error.InvalidOverlap;
    if (slicesOverlap(tag, ciphertext) or slicesOverlap(tag, plaintext)) return error.InvalidOverlap;
    try validateAeadOutputOverlap(plaintext, &.{}, key, nonce, aad_parts);
}

fn validateAeadOutputOverlap(
    payload_out: []const u8,
    tag_out: []const u8,
    key: []const u8,
    nonce: []const u8,
    aad_parts: []const []const u8,
) ProviderError!void {
    if (slicesOverlap(payload_out, key) or slicesOverlap(payload_out, nonce) or
        slicesOverlap(tag_out, key) or slicesOverlap(tag_out, nonce))
    {
        return error.InvalidOverlap;
    }
    for (aad_parts) |part| {
        if (slicesOverlap(payload_out, part) or slicesOverlap(tag_out, part)) return error.InvalidOverlap;
    }
}

fn slicesOverlap(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;
    const a_start = @intFromPtr(a.ptr);
    const b_start = @intFromPtr(b.ptr);
    return a_start < b_start + b.len and b_start < a_start + a.len;
}

fn sameSlice(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    if (a.len == 0) return true;
    return @intFromPtr(a.ptr) == @intFromPtr(b.ptr);
}
