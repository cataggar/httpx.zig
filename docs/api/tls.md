# TLS API

The TLS module implements TLS 1.2/1.3 using Zig cryptographic primitives and
standard-library TLS state and wire-format helpers.

::: warning Production trust is not implemented
The current client handshake does not implement production public-CA trust.
`TLSConfig.verify_server` still selects the legacy self-signed verification
path, and `ca_bundle_path` is not wired into it. Do not use this path for
authenticated public HTTPS, including Azure. The primitive implementation
described below does not fix or bypass these pending trust/handshake changes.
:::

::: warning TLS implementation status
The existing TLS engine includes:
- **TLS 1.2 and 1.3** with full handshake support (RFC 5246 / RFC 8446)
- **Key exchange:** X25519 (TLS 1.2/1.3)
- **AEAD cipher suites:** ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM
- **ALPN negotiation** (RFC 7301) for automatic HTTP/2 selection with HTTP/1.1 fallback
- **Handshake message encryption** (TLS 1.3)
- **X.509 certificate parsing** (production chain policy remains pending)
- **Custom record-layer encryption/decryption**
:::

## Supported Features

| Feature | TLS 1.2 | TLS 1.3 |
|---------|---------|---------|
| X25519 key exchange | ✅ | ✅ |
| AES-128-GCM | ✅ | ✅ |
| AES-256-GCM | ✅ | ✅ |
| ChaCha20-Poly1305 | ✅ | ✅ |
| ECDSA P-256 certificate signing | -- | ✅ |
| Certificate loading (PEM) | ✅ | ✅ |
| Production certificate chain verification (client-side) | Pending | Pending |
| ALPN negotiation | ✅ | ✅ |
| SNI extension | ✅ | ✅ |
| Handshake message encryption | -- | ✅ |
| Cipher suite selection from client list | -- | ✅ |

## Architecture

```
tls.zig              -- High-level Connection, TlsConfig, TlsSession, record-layer AEAD encrypt/decrypt
├── client.zig       -- TLS 1.2/1.3 client handshake, X25519 key exchange, cipher suite negotiation
├── server.zig       -- TLS 1.2/1.3 server handshake, ServerHello, cipher selection
├── alpn.zig         -- ALPN protocol negotiation
├── trust.zig        -- Provider-neutral trust policy, sources, limits, and peer-verification contract
├── cert_signature.zig -- Narrow certificate-signature verifier bridge
├── cert_crypto.zig  -- Certificate-signature adapter to the selected primitive provider
├── crypto/standard.zig -- Pure-Zig CryptoProvider implementation (not yet a handshake backend)
└── errors.zig       -- Unified TLS error set and alert conversion
```

## Standard CryptoProvider Implementation

`httpx.StandardCryptoProvider` implements the borrowed `CryptoProvider` contract
using `std.crypto`. It is a working primitive backend, not yet selectable through
`TLSConfig` or `ClientConfig`: handshakes and record protection still need their
provider-neutral state conversion. No option silently selects this provider
while continuing to use another implementation.

```zig
var standard = httpx.StandardCryptoProvider.init(io, thread_safe_allocator);
const crypto = standard.provider();
var transcript = try crypto.hashCreate(allocator, .sha256);
defer transcript.deinit();
try transcript.update(handshake_bytes);
```

Keep `standard` at a stable address and alive for all borrowed handles.
Its `Io` implementation and scratch allocator must also outlive those handles.
Shared use requires a concurrent `Io` and thread-safe scratch allocator.
Hash/key handles are individually owned; use `clone` for transcript copies
and `take` for ownership transfer, and destroy each handle exactly once.

Implemented operations:

- SHA-1/256/384/512 transcripts, snapshots, independent clones, multipart HMAC,
  HKDF extract/expand, and TLS 1.2 PRF.
- AES-128/256-GCM and ChaCha20-Poly1305 with detached tags, multipart AAD,
  in-place operation, and output wiping on operational/authentication failure.
- X25519, P-256 and P-384 key generation/agreement; ML-KEM-768 key generation,
  encapsulation and decapsulation (including standard implicit rejection).
- ECDSA P-256/SHA-256, P-384/SHA-384 and Ed25519 signing and verification.
  Signing imports accept raw scalars/seeds, unencrypted SEC1 EC private keys,
  and unencrypted PKCS#8 EC/Ed25519 private keys. Optional embedded public keys
  are checked against the derived public key, including compressed SEC1 points.
  RFC 5958 version-one containers require their public key; PKCS#8 attributes
  remain explicitly unsupported. Malformed containers and mismatched curves,
  key lengths or public keys are rejected.
- RSA PKCS#1 v1.5 and PSS verification for 2048/3072/4096-bit keys, with bounded
  canonical PKCS#1 public-key DER and modulus-sized signatures. PSS uses the
  scheme hash for MGF1 and a digest-sized salt.
- Constant-time comparison.

Entropy comes exclusively from `Io.randomSecure`; entropy failure is returned
and never falls back to `Io.random`. Owned private-key, shared-secret, transcript,
and key-derivation scratch storage is wiped before destruction.
**RSA signing remains pending** in this backend; capabilities report it as
unsupported. SHA-1 primitive availability is not permission to accept SHA-1
certificates or negotiate legacy signatures; that decision belongs to policy.

### Certificate-signature adapter

`httpx.CryptoCertificateVerifier.init(crypto)` creates an independently owned,
stable-address adapter. Its `.verifier()` handle can populate
`VerifyPeerRequest.signature_verifier`. It parses bounded SPKI/algorithm
encodings and delegates every signature verification to the selected provider,
without fallback or trust decisions. Supported certificate signatures are RSA
PKCS#1 SHA-1/256/384/512, P-256/SHA-256, P-384/SHA-384, and Ed25519.
RSA-PSS certificate AlgorithmIdentifiers, restricted PSS SPKIs, other
curve/hash combinations and unsupported parameters fail explicitly.

### Remaining integration

No target currently has production default/custom-root verification through
this implementation. Zig 0.16's `Certificate.Parsed.verify` checks issuer,
validity and signature, but does not implement the required CA/basic
constraints, key usage, path constraints and critical-extension policy.
Simply wrapping `Certificate.Bundle.verify` would not supply production PKI.
Root discovery, bounded path construction and policy, SAN/IP matching, trust
context ownership, and handshake trust dispatch remain required for issue #4.
Provider-neutral client/server transcripts, key shares and records, RSA
private-key loading/signing, and an instrumented whole-handshake dispatch test
remain for issue #7.

The existing `zig build test-tls-provider` runner covers primitives and the
certificate adapter; both also run under `zig build test`. Neither needs a
live endpoint or native cryptographic library.

## Trust Provider Contract

The public trust-provider contract is the first foundation for secure,
provider-neutral X.509 validation. It is available as `httpx.TrustProvider`
and `httpx.tls.TrustProvider`.

::: warning Foundation API
The contract is not connected to the TLS handshakes yet. Existing
`TLSConfig.verify_server` and `ca_bundle_path` runtime behavior is unchanged
in this foundation change. Declaring a `TrustSource` does not activate it
until the later trust-context and handshake integration lands.
:::

### Ownership and concurrency

`TrustProvider` and `CertificateSignatureVerifier` are borrowed, type-erased
handles. Their context owners must outlive all TLS contexts and sessions using
them. Copying a handle does not transfer ownership, neither handle has a
`deinit` method, and callbacks must not retain request slices.

Provider state is immutable after initialization and verification must be safe
for concurrent calls. Peer DER, expected identities, signature inputs, and the
scratch allocator are borrowed only for one synchronous call. A future
standard provider will own copied/indexed trust anchors separately; it is
intentionally not represented by a non-functional stub in this foundation.

### Verification request

```zig
pub const VerifyPeerRequest = struct {
    role: PeerRole,                         // .server or .client
    chain_der: []const []const u8,          // leaf first; unordered intermediates
    expected_identity: ?PeerIdentity,       // .dns_name or parsed .ip_address
    now_seconds: i64,
    signature_verifier: CertificateSignatureVerifier,
    scratch_allocator: std.mem.Allocator,
    limits: TrustLimits = .{},
};
```

The type-erased `TrustProvider.verifyPeer` performs common certificate
count/size limit checks and then dispatches to the provider. `TrustLimits`
bounds peer certificate count, individual and aggregate DER bytes, path depth,
and path-construction candidate attempts.

`CertificateSignatureVerifier` receives borrowed signature
`AlgorithmIdentifier` components, issuer SubjectPublicKeyInfo DER, exact TBS
certificate DER, and signature bytes. `CryptoCertificateVerifier` implements this seam without moving hostname, time,
chain, or root policy into the crypto provider.

### Declarative sources and policy

```zig
const secure_default: httpx.ServerAuthentication = .{
    .verify = .system,
};

const private_pki: httpx.ServerAuthentication = .{
    .verify = .{
        .custom_only = .{ .pem_file_path = "private-roots.pem" },
    },
};
```

`TrustSource` supports:

- `.system`: platform roots only.
- `.system_plus_custom`: platform roots merged with a PEM file, in-memory PEM,
  or an in-memory DER certificate list.
- `.custom_only`: only the supplied CA material.
- `.provider`: a caller-owned borrowed `TrustProvider`.

CA source slices are borrowed until runtime trust-context initialization
finishes; retained material must be copied by that owner. The only policy tag
for bypassing certificate chain, identity, and time checks is
`.dangerously_insecure_skip_certificate_verification`. TLS handshake
proof-of-possession remains a separate responsibility and is never part of
`TrustProvider`.

### Trust errors

Specific categories include malformed certificates/chains, unknown CA,
hostname mismatch, expired/not-yet-valid certificates, invalid usage or path
constraints, invalid/unsupported certificate signatures, trust-store load or
empty-anchor failures, bounded-input/path-search failures, invalid trust
configuration, and allocation failure. Local trust errors map to the closest
TLS alert without erasing the original local error.

## TlsConfig (Client)

Configuration for TLS client connections.

### Cancellation and retry boundary

`TLSSession.handshake` never implicitly retries on the same TLS stream.
Without a reconnect callback it makes exactly one attempt. The optional legacy
reconnect callback is considered only for transport I/O failure or truncation.
Other explicitly reported errors, including certificate, protocol,
authentication, cancellation and timeout errors, do not trigger it.
A reconnect callback must supply a fresh connection and honor the
operation's cancellation and deadline policy. Request operations should own
retries and leave the callback unset.

Record I/O preserves underlying `Cancelled` and `Timeout` errors. The standard
`Io.Reader`/`Writer` handshake interfaces have narrower error sets, however, so
their socket adapters or the enclosing operation must retain the concrete
transport error. A context-owning caller can use `IoContext.unwrapAfterBlocking`
after handshake/read/write/flush to restore cancellation/deadline precedence.
This does not itself interrupt blocked I/O: the underlying socket transport must
provide that behavior. Discard a connection after a failed record operation;
partially transferred records are not resumable by retrying the operation.

```zig
pub const TlsConfig = struct {
    allocator: Allocator,
    alpn_protocols: []const []const u8 = &.{"http/1.1"},
    verify_server: bool = true,
    ca_bundle_path: ?[]const u8 = null,
};
```

### Factory Methods

| Method | Description |
|--------|-------------|
| `init(allocator)` | Default config (verify server, HTTP/1.1 only) |
| `insecure(allocator)` | Skip server verification |
| `withH2(allocator)` | Advertise h2 + http/1.1 ALPN |
| `insecureWithH2(allocator)` | Insecure + h2 ALPN |
| `withH3(allocator)` | Low-level experimental h3 ALPN configuration; no public QUIC runtime |
| `insecureWithH3(allocator)` | Low-level experimental h3 ALPN configuration without verification |

## ServerTlsConfig

Configuration for TLS server connections. Holds loaded certificate chain and private key in DER format.

```zig
pub const ServerTlsConfig = struct {
    cert_chain_der: []const []const u8 = &.{},
    key_der: ?[]const u8 = null,
    allocator: ?Allocator = null,
    ecdsa_keypair: ?crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair = null,
};
```

### Loading from PEM Files

```zig
const server_tls = try tls.loadServerTlsConfig(allocator,
    "examples/certs/server_ec.crt",
    "examples/certs/server_ec.key",
);
defer server_tls.deinit();
```

## Server Configuration

Enable TLS on the server via `ServerConfig`:

```zig
var server = httpx.Server.initWithConfig(allocator, .{
    .host = "127.0.0.1",
    .port = 8443,
    .tls_enabled = true,
    .tls_cert_path = "examples/certs/server_ec.crt",
    .tls_key_path = "examples/certs/server_ec.key",
    .tls_alpn_protocols = &.{ "h2", "http/1.1" },
    .http2_enabled = true,
    .http3_enabled = false,
});
```

::: tip ALPN Default
The default `tls_alpn_protocols` is `&.{ "h2", "http/1.1" }`.
:::

The server automatically loads the certificate chain and private key on the first TLS connection. ALPN negotiation selects HTTP/1.1 or HTTP/2.

ALPN uses the RFC 7301 network format: ClientHello carries a u16-length
`ProtocolNameList`; TLS 1.2 returns the selected one-element list in
ServerHello, while TLS 1.3 returns it in EncryptedExtensions. Empty names,
truncated lists, duplicate ALPN extensions, and trailing bytes are rejected.

## Connection

The `Connection` struct represents an established TLS session over a TCP socket.

```zig
pub const Connection = struct {
    allocator: Allocator,
    socket: *Socket,
    negotiated_alpn: NegotiatedAlpn,
    tls_version: ProtocolVersion,
    is_server: bool,
    connected: bool,
    app_write_key: ?[32]u8,
    app_write_iv: ?[12]u8,
    app_read_key: ?[32]u8,
    app_read_iv: ?[12]u8,
    write_seq: u64,
    read_seq: u64,
    hs_write_seq: u64,
    hs_read_seq: u64,
    cipher_suite: ?CipherSuite,
};
```

### Methods

| Method | Description |
|--------|-------------|
| `negotiatedAlpn()` | Get the negotiated ALPN protocol string |
| `isHttp2()` | Returns true if HTTP/2 was negotiated |
| `isHttp3()` | Returns true if HTTP/3 was negotiated |
| `tlsVersion()` | Returns the negotiated TLS protocol version |
| `sendAlert(level, desc)` | Send a TLS alert to the peer |
| `closeNotify()` | Send close_notify alert for clean shutdown |
| `reader()` | Get an `AnyReader` for reading decrypted data |
| `writer()` | Get an `AnyWriter` for writing encrypted data |
| `read(buffer)` | Read decrypted data from the connection |
| `write(data)` | Seal and send at most one 16,384-byte plaintext record; returns plaintext bytes consumed |
| `writeAll(data)` | Send the complete plaintext buffer as independently framed records |

## Client Handshake

Perform a full TLS 1.2 or 1.3 client handshake:

```zig
const connection = try tls.connectClient(allocator, socket, &config, "example.com");
defer connection.closeNotify();
```

## Server Handshake

Accept a TLS connection on the server side:

```zig
const connection = try tls.acceptServer(allocator, socket, alpn_protocols, server_tls_config);
defer connection.closeNotify();
```

## ALPN Negotiation

The ALPN module provides protocol negotiation between client and server:

```zig
// Protocol detection
try std.testing.expect(alpn.isHttp2("h2"));
try std.testing.expect(alpn.isHttp3("h3"));
try std.testing.expect(alpn.isHttp1x("http/1.1"));
```

## Certificate Verification

The current handshake certificate path predates the provider contract and
uses `std.crypto.Certificate` directly. It parses certificates, verifies
adjacent signatures, checks time/hostname data, and supports the internal CA
bundle path when supplied directly to the low-level client.

The new `TrustProvider` sources are deliberately not advertised as active
verification behavior yet. Full X.509 parsing/path construction, platform and
custom root loading, and TLS 1.2/1.3 handshake integration are deferred.

### Certificate-Related Errors

| Error | Description |
|-------|-------------|
| `TlsCertificateExpired` | Certificate validity period has expired |
| `TlsCertificateNotYetValid` | Certificate validity period has not yet started |
| `TlsUnknownCa` | No path reaches a configured trust anchor |
| `TlsHostnameMismatch` | DNS/IP identity doesn't match the certificate |
| `TlsMalformedCertificate` / `TlsMalformedCertificateChain` | Certificate DER or chain structure is invalid |
| `TlsCertificateUsageInvalid` | Leaf usage/EKU is invalid for the peer role |
| `TlsCertificateConstraintViolation` | A path constraint rejects the chain |
| `TlsCertificateSignatureInvalid` | A certificate-edge signature is invalid |
| `TlsUnsupportedCertificateSignatureAlgorithm` | No configured verifier supports the signature algorithm |
| `TlsTrustStoreLoadFailed` / `TlsNoTrustAnchors` | Trust material could not provide a usable store |
| `TlsCertificateTooLarge` / `TlsCertificateChainTooLarge` | Input exceeds configured byte/count limits |
| `TlsCertificatePathTooDeep` / `TlsCertificatePathSearchLimitExceeded` | Path work exceeds configured limits |

`TlsCertificateNotVerified` remains in the legacy handshake path until trust
integration replaces that ambiguous result with the specific categories above.

## Types

### CipherSuite

Supported cipher suites:

| Suite | TLS Version | Notes |
|-------|-------------|-------|
| `AES_128_GCM_SHA256` | 1.3 | Default |
| `AES_256_GCM_SHA384` | 1.3 | |
| `CHACHA20_POLY1305_SHA256` | 1.3 | |
| `ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 1.2 | |
| `ECDHE_RSA_WITH_AES_256_GCM_SHA384` | 1.2 | |
| `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` | 1.2 | |

### Named Groups

Supported elliptic curves for key exchange:

| Group | Notes |
|-------|-------|
| `x25519` | Default, only key exchange actually negotiated by both client and server |

### Error Set

All TLS errors are unified in `TlsError`:

| Error | Description |
|-------|-------------|
| `TlsCloseNotify` | Clean shutdown |
| `TlsBadRecordMac` | AEAD authentication failed |
| `TlsCertificateExpired` | Certificate validity expired |
| `TlsHostnameMismatch` | Hostname doesn't match certificate |
| `TlsHandshakeFailure` | No acceptable parameters negotiated |
| `TlsUnsupportedCipherSuite` | Unsupported cipher suite |

**PEM Loading Errors** (returned by `loadCertChain`/`loadPrivateKey`, not part of unified `TlsError`):

| Error | Description |
|-------|-------------|
| `TlsInvalidPem` | PEM decoding failed |
| `TlsNoCertificates` | No certificates found in PEM file |
| `TlsInvalidPrivateKey` | Private key PEM decoding failed |

See `errors.zig` for the full `TlsError` set.
