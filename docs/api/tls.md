# TLS API

The TLS module implements TLS 1.2/1.3 using an explicit `CryptoProvider` for
handshakes and records, with a pure-Zig standard implementation.

::: warning Native qualification
`TLSConfig`, `connectClient`, and high-level `ClientConfig`/`Client.open`
accept a selected provider and dispatch certificate policy to the
[canonical trust implementation](./standard-trust.md). Paired adapters and
the canonical root factory are connected through the streaming lease paths.
Native platform policy and optional-backend qualification remain separate
release gates; unsupported system metadata still fails closed.
:::

::: warning TLS implementation status
The existing TLS engine includes:
- **TLS 1.2 and 1.3** with full handshake support (RFC 5246 / RFC 8446)
- **Key exchange:** capability-filtered X25519, P-256, P-384; the server also accepts TLS 1.3 hybrid X25519/ML-KEM-768
- **AEAD cipher suites:** ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM
- **ALPN negotiation** (RFC 7301) for automatic HTTP/2 selection with HTTP/1.1 fallback
- **Handshake message encryption** (TLS 1.3)
- **X.509 certificate policy:** the canonical bounded path validator, not a second runtime policy engine
- **Custom record-layer encryption/decryption**
:::

## Supported Features

| Feature | TLS 1.2 | TLS 1.3 |
|---------|---------|---------|
| X25519 key exchange | ✅ | ✅ |
| AES-128-GCM | ✅ | ✅ |
| AES-256-GCM | ✅ | ✅ |
| ChaCha20-Poly1305 | ✅ | ✅ |
| ECDSA P-256/P-384 and RSA certificate signing | ✅ | ✅ |
| Certificate loading (PEM) | ✅ | ✅ |
| Canonical custom-root certificate verification (client-side) | ✅ | ✅ |
| ALPN negotiation | ✅ | ✅ |
| SNI extension | ✅ | ✅ |
| Handshake message encryption | -- | ✅ |
| Capability-filtered cipher suite selection from client list | ✅ | ✅ |

## Architecture

```
tls.zig              -- High-level Connection, TlsConfig, TlsSession, record-layer AEAD encrypt/decrypt
├── client.zig       -- Provider-owned client transcripts, key shares and handshake state
├── server.zig       -- Server entry point for server_runtime.zig
├── server_identity.zig -- Owned, serialized provider signing-key handle
├── alpn.zig         -- ALPN protocol negotiation
├── trust.zig        -- Provider-neutral trust policy, sources, limits, and peer-verification contract
├── cert_signature.zig -- Narrow certificate-signature verifier bridge
├── cert_crypto.zig  -- Certificate-signature adapter to the selected primitive provider
├── standard_trust.zig -- Canonical immutable roots and bounded path policy
├── crypto/standard.zig -- Pure-Zig CryptoProvider implementation
├── crypto/tls_primitives.zig -- Explicit-provider standalone TLS helpers
└── errors.zig       -- Unified TLS error set and alert conversion
```

## Standard CryptoProvider Implementation

`httpx.StandardCryptoProvider` implements the borrowed `CryptoProvider` contract
using `std.crypto`. `TLSConfig.crypto_provider` selects a borrowed provider for
the entire client handshake and subsequent records. `null` uses a standard
implementation owned by the session/connection; no pointer to a temporary
standard provider is transferred by `connectClient`. Capability refusal and
callback errors never trigger a different primitive backend.
`ClientConfig.tls_crypto_provider` selects the same borrowed provider for
high-level HTTP/1.1 and HTTP/2 operations and their pooled TLS sessions.

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

The primitive semantic ABI is **2**. `CryptoProvider`, `VTable`, and
`Capabilities` retain their ABI-1 byte layouts. Existing hash tags 0–3 remain
unchanged; raw identifier-only `HashAlgorithm.md5` appends tag 4, bit `0x10`.
The consumer admits ABI 1 and 2 without relabeling descriptors. Unknown
versions fail with `IncompatibleAbiVersion` before provider callbacks. ABI-1
MD5 creation fails before even the capability callback; raw hash masks are
limited to `0x0f` for ABI 1 and `0x1f` for ABI 2. Compatibility is directional:
an old consumer may reject a new ABI-2 provider, including a standard provider
with MD5 disabled. Admission of both versions does not make their identities
equivalent: the exact `(abi_version, context, vtable)` must still match.

### Standalone helper migration

Public TLS encryption, decryption, PRF, HKDF, traffic-key and encrypted-handshake
helpers require a `CryptoProvider` argument and propagate failures. AEAD helpers
take a provider algorithm such as `.aes_128_gcm`, not a `std.crypto` type;
`deriveHandshakeSecret13` also takes a scratch allocator. Callers must handle
the error union with `try`/`catch`. This intentional signature change prevents
standalone helpers from silently bypassing the selected backend. Existing
provider vtable layouts and trust requests are unchanged.

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
- RSA PKCS#1 v1.5 and PSS signing/verification for 2048/3072/4096-bit keys, with bounded
  canonical PKCS#1 public-key DER and modulus-sized signatures. PSS uses the
  scheme hash for MGF1 and a digest-sized salt. Private signing is blinded and
  checks the result before publishing it; unsupported or inconsistent
  PKCS#1/PKCS#8 key parameters fail explicitly.
- Constant-time comparison.

Entropy comes exclusively from `Io.randomSecure`; entropy failure is returned
and never falls back to `Io.random`. Owned private-key, shared-secret, transcript,
and key-derivation scratch storage is wiped before destruction.
SHA-1 primitive availability is not permission to accept SHA-1 certificates
or negotiate legacy signatures.

### Certificate-signature adapter

`httpx.CryptoCertificateVerifier.init(crypto)` creates an independently owned,
stable-address adapter. Its `.verifier()` handle can populate
`VerifyPeerRequest.signature_verifier`. It parses bounded SPKI/algorithm
encodings and delegates every signature verification to the selected provider,
without fallback or trust decisions. Supported certificate signatures are RSA
PKCS#1 SHA-256/384/512, bounded RSA-PSS, P-256/SHA-256, P-384/SHA-384, and Ed25519.
Restricted PSS key parameters are enforced before dispatch. SHA-1 certificate
signatures, unsupported curve/hash combinations and unsupported parameters
fail explicitly.

The `metadataHasher(options)` callback captures identifier permission at
construction. Even direct callback calls enforce that permission, exact digest
sizes, provider capability checks, and output clearing on failure. Construct a
new hasher to change the captured permission; changing descriptor options alone
cannot enable a permission denied at construction.

### Same-provider certificate adapters

`TLSConfig.certificate_crypto` and the raw TLS client's
`Options.certificate_crypto` accept a borrowed `*CryptoCertificateVerifier`.
High-level clients forward `ClientConfig.tls_certificate_crypto`.
Supply the same adapter instance used by a policy's expected signature handle:

```zig
var adapter = httpx.CryptoCertificateVerifier.init(selected_crypto.provider());
const config: tls.TLSConfig = .{
    .allocator = allocator,
    .crypto_provider = selected_crypto.provider(),
    .certificate_crypto = &adapter,
    .server_authentication = .{ .verify = .{ .provider = policy_provider } },
};
```

Runtime compares the adapter's provider ABI version, context, and vtable with
the actual selected TLS provider before I/O and again before certificate
verification. A different provider, omitted explicit provider, or insecure
configuration fails with `TlsInvalidTrustConfiguration`; runtime never
downcasts an erased signature-verifier context to discover its provider.
The pre-I/O check is at the TLS boundary; high-level clients can already have
established TCP or a proxy tunnel before reaching it.
The exact configured adapter's signature handle reaches the trust callback.
For a `PolicyBinding`, this is the same context and vtable returned by
`binding.signatureVerifier()`. Construct the binding's signature and metadata
handles from that adapter; another adapter instance is rejected even if it
wraps an identical primitive-provider descriptor.
When no adapter is supplied, existing custom trust-provider callbacks continue
to receive the ordinary per-handshake verifier.

The adapter/provider/binding/root owners must remain stable, immutable during
use, and alive through all pooled TLS sessions and leases. The TLS configuration
borrows them and does not destroy them. These optional fields extend
source-level TLS/client configuration; they do not change ABI-v1 request or
existing provider/verifier vtable layouts. Policy time remains current for each
verification request rather than being taken from root-store load time.

### Canonically bound high-level clients

Create both handles from the same stable adapter using the existing root
factory, then supply that adapter and selected provider to the client:

```zig
var selected = httpx.StandardCryptoProvider.init(io, allocator);
var roots = try httpx.tls.TrustContext.init(allocator, io, .{
    .source = .system,
});
defer roots.deinit();
var adapter = httpx.CryptoCertificateVerifier.init(selected.provider());
var binding = try roots.bind(&adapter, .{ .allow_sha1_identifiers = true });
var client = try httpx.Client.tryInitWithConfig(allocator, .{
    .tls_crypto_provider = selected.provider(),
    .tls_certificate_crypto = &adapter,
    .server_authentication = .{ .verify = .{ .provider = binding.provider() } },
});
defer client.deinit();
```

System discovery remains subject to the platform profile and may reject
unsupported metadata. Identifier hashing has two independent gates, described
below; this example explicitly enables the binding's SHA-1 identifier gate,
not SHA-1 certificate signatures.

`ClientConfig.server_authentication` overrides the legacy `verify_ssl`
selection, including per-request overrides. `tls_trust_limits` bounds the
actual handshake's certificate and path processing. `Client.makeTlsConfig`
forwards these fields with its allocator and the requested ALPN list; any
resulting session must end before that client is destroyed.

The immutable client configuration is shared by its operations and pool.
Changing or moving a borrowed provider, adapter, binding, or roots while those
operations or pooled sessions exist is unsupported. HTTP/3 and Unix-plus-TLS
restrictions, cancellation/deadline handling, and embedding-owned policy are
unchanged.

### Metadata-only certificate digests

`CryptoCertificateVerifier.metadataHasher(options)` returns a borrowed
`MetadataDigest` with the same context as `adapter.verifier()`. Its `hash`
method enforces per-binding identifier policy and uses the selected provider's
`hashCreate`, `update`, `snapshot`, and `deinit` operations. It never substitutes
stdlib hashing or an operating-system certificate-chain engine:

```zig
var adapter = httpx.CryptoCertificateVerifier.init(selected_crypto.provider());
const hasher = adapter.metadataHasher(.{ .allow_sha1_identifiers = true });
var identifier: [20]u8 = undefined;
try hasher.hash(allocator, .sha1, certificate_der, &identifier);
```

The existing `digestMetadata(..., options)` remains available for individual
calls with the same buffer, error, and cleanup guarantees.
SHA-1 identifier hashing is denied unless explicitly enabled;
the selected backend must independently advertise SHA-1 hashing support.
For the optional SymCrypt TLS provider this additionally requires its
independent `allow_sha1_identifier_hash = true` deployment option. The policy
option is named `allow_sha1_identifiers`; neither opt-in substitutes for the
other.
This permission changes no signature, HMAC, HKDF, or PRF capability. The
certificate-signature adapter rejects SHA-1 signatures even when metadata
hashing is enabled.

ABI-2 raw MD5 identifier hashing requires two independent, default-off gates:
`StandardCryptoProvider.Options.allow_md5_identifier_hash` and metadata
`Options.allow_md5_identifiers`. `StandardCryptoProvider.init(io, allocator)`
and `Capabilities.all()` keep MD5 disabled. Use `initWithOptions` to opt in:

```zig
var selected_md5 = httpx.StandardCryptoProvider.initWithOptions(io, allocator, .{
    .allow_md5_identifier_hash = true,
});
var adapter_md5 = httpx.CryptoCertificateVerifier.init(selected_md5.provider());
const hasher_md5 = adapter_md5.metadataHasher(.{ .allow_md5_identifiers = true });
var identifier_md5: [16]u8 = undefined;
try hasher_md5.hash(allocator, .md5, public_identifier_bytes, &identifier_md5);
```

The one-shot `digestMetadata` options expose the same independent MD5 gate.
Neither MD5 gate enables SHA-1 identifiers. The factory captures one of four
callback permissions: neither legacy hash, SHA-1 only, MD5 only, or both.
All use the original adapter context. Direct callback invocation and later
descriptor-option mutation cannot exceed the captured permission.
Keep provider deployment options immutable while borrowed descriptors or
handles are in use.

MD5 is never available for HMAC, HKDF, TLS PRF, or signatures. Keyed support
queries, wrappers, and direct standard-provider callbacks reject it, including
empty requests; fabricated capability bits cannot authorize it. The standard
provider also checks its deployment gate in direct raw `hashCreate` calls.
The primitive alone does not define CTL matching. The separate
[documented Disallowed profile](./standard-trust.md#documented-disallowed-deny-identities)
uses selected-provider P15/TBS and P25/raw-key identities under these gates;
it does not enable bare-MD5 CTL selectors or claim full Windows chain-policy
equivalence. Native production qualification remains a separate gate.

Output must be exactly the algorithm's digest length. Every error clears the
provided output, including invalid length, disabled/unsupported algorithms,
allocation failure, and backend failure. Hash state is allocated with the
caller's scratch allocator and destroyed on every path; no input, output, or
hash handle is retained. Concurrent calls require a thread-safe provider and
scratch allocator. Borrowed verifier handles still require their adapter and
provider owners to remain at stable addresses and alive.

A fingerprint match alone does not establish a trust anchor. A `PolicyBinding`
rejects a different signature context or vtable before private policy dispatch;
the canonical policy still owns anchor selection and certificate validation.
This primitive adapter does not change `VerifyPeerRequest` or existing
verifier/provider vtable layouts. Raw MD5 requires primitive ABI 2. The canonical
`roots.bind` factory uses this production adapter directly. Platform CTL
interpretation and native qualification retain their separate release gates.

The public `connectClient` regression tests exercise the actual binding and
metadata descriptor through TLS 1.2/1.3 handshakes, application records, and
TLS 1.3 KeyUpdate. They assert the request handle equals
`binding.signatureVerifier()`, selected hash/signature/record callbacks execute,
and mismatched adapters/providers, independent identifier gates, and provider
failures reject without fallback. The binding fixture uses an exact certificate
pin, identity/time checks, and its issuer signature; it is not a general PKIX
policy or qualification of a platform trust store.

### Canonical composition and qualification

The canonical policy files are unchanged by this runtime port. The handshake
uses `TrustContext.init(allocator, io, .{ .source = source,
.load_time_seconds = now })`; verification time is sampled again when checking
the peer, not taken from the root-load snapshot. See the canonical trust
documentation for its supported profile and platform limits.

The canonical `roots.bind(adapter_pointer, metadata_digest.Options)` factory
is exercised with the production adapter through public `connectClient` and
`Client.open` HTTP/1.1 and HTTP/2 leases. TLS 1.2/1.3 fixtures use a real local
certificate chain, synthetic fingerprint restrictions, and selected-provider
hash/signature/record spies. They cover independent identifier gates, provider
errors, path limits, pool reuse, and cleanup. Context-only and vtable-only
provider mismatches reject even with the exact bound signature handle supplied;
an absent or different adapter is also rejected.

These hermetic cases do not qualify an operating-system store, public-CA
endpoint, native cryptographic backend, or cancellation latency. No alternate
factory, DN normalization, or duplicate certificate policy is introduced.

The existing `zig build test-tls-provider` runner covers primitives and the
certificate adapter; both also run under `zig build test`. Neither needs a
live endpoint or native cryptographic library. `connectClient` tests use
authenticated loopback TLS 1.2/1.3, including returned-provider identity,
record/capability rejection, KeyUpdate, and context-aware I/O. Build the
opt-in fixture probe with `zig build example-tls_provider_interop -j2`;
it is excluded from `run-all-examples`.

## Trust Provider Contract

The public trust-provider contract is the first foundation for secure,
provider-neutral X.509 validation. It is available as `httpx.TrustProvider`
and `httpx.tls.TrustProvider`.

::: warning Borrowed trust configuration
The contract is connected to standalone and streaming client handshakes.
Select high-level providers through `ClientConfig`; copying their handles
does not extend the lifetime of the owners.
:::

### Ownership and concurrency

`TrustProvider` and `CertificateSignatureVerifier` are borrowed, type-erased
handles. Their context owners must outlive all TLS contexts and sessions using
them. Copying a handle does not transfer ownership, neither handle has a
`deinit` method, and callbacks must not retain request slices.

Provider state is immutable after initialization and verification must be safe
for concurrent calls. Peer DER, expected identities, signature inputs, and the
scratch allocator are borrowed only for one synchronous call. The canonical
`TrustContext` owns copied/indexed trust anchors separately.

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

Record I/O preserves underlying `Cancelled` and `Timeout` errors. Context-aware
handshake/read/write methods use cancellable socket operations, including
KeyUpdate responses. A record's sequence advances before a potentially partial
send, and failed writes poison the write state rather than reuse the nonce.
The standard
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
    crypto_provider: ?CryptoProvider = null,
    server_authentication: ?ServerAuthentication = null,
    trust_limits: TrustLimits = .{},
    alpn_protocols: []const []const u8 = &.{"http/1.1"},
    verify_server: bool = true,
    ca_bundle_path: ?[]const u8 = null,
};
```

`server_authentication` overrides legacy `verify_server`/`ca_bundle_path`.
Otherwise verification uses system roots, or custom-only roots from
`ca_bundle_path`; `verify_server = false` is the explicit legacy insecure path.
Peer proof-of-possession is still required in insecure mode.

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

Configuration for TLS server connections. Owns a copied certificate chain,
private-key material, and a serialized imported signing handle. An explicitly
selected provider remains borrowed and must outlive configuration and sessions.

```zig
pub const ServerTlsConfig = struct {
    cert_chain_der: []const []const u8 = &.{},
    key_der: ?[]const u8 = null,
    allocator: ?Allocator = null,
    ecdsa_keypair: ?crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair = null,
    crypto_provider: ?CryptoProvider = null,
    // Additional owned identity state is maintained by init/deinit.
};
```

### Loading from PEM Files

```zig
var server_tls = try tls.loadServerTLSConfig(allocator,
    "examples/certs/server_ec.crt",
    "examples/certs/server_ec.key",
);
defer server_tls.deinit();
```

Use `loadServerTLSConfigWithProvider(allocator, io, cert_path, key_path,
selected_provider)` or `ServerTLSConfig.init(allocator, io, chain_der,
private_key, selected_provider)` to select a backend. Do not destroy the config
while a server handshake/signing operation is active.

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
`ServerConfig.tls_crypto_provider` selects the borrowed server backend.

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
| `closeNotify()` | Send close_notify alert, then release connection-owned state |
| `deinit()` | Non-I/O cleanup; does not close the borrowed socket or destroy the selected provider |
| `reader()` | Get an `AnyReader` for reading decrypted data |
| `writer()` | Get an `AnyWriter` for writing encrypted data |
| `read(buffer)` | Read decrypted data from the connection |
| `write(data)` | Seal and send at most one 16,384-byte plaintext record; returns plaintext bytes consumed |
| `writeAll(data)` | Send the complete plaintext buffer as independently framed records |
| `readWithContext(buffer, context)` | Context-aware decrypted read |
| `writeWithContext(data, context)` / `writeAllWithContext(data, context)` | Context-aware record writes |

## Client Handshake

Perform a full TLS 1.2 or 1.3 client handshake:

```zig
var connection = try tls.connectClient(allocator, socket, &config, "example.com");
defer connection.closeNotify();
```

## Server Handshake

Accept a TLS connection on the server side:

```zig
var connection = try tls.acceptServer(allocator, socket, alpn_protocols, server_tls_config);
defer connection.closeNotify();
```

The four-argument `acceptServer` keeps its existing blocking behavior and
socket-timeout policy, as does the high-level server's existing call path.
Opt in to cancellation-aware **handshake** I/O with
`tls.acceptServerWithIo(allocator, socket, protocols, config, options)`.
`tls.ServerHandshakeIoOptions` borrows the canonical context exposed by
`httpx.io_context`:

| Option | Meaning |
| --- | --- |
| `context: *const IoContext` | Required borrowed parent; cancellation and the earliest parent deadline propagate to every handshake I/O operation. |
| `read_timeout_ms: ?u64 = null` | Budget for one complete incoming handshake message, including partial TLS headers, payloads, authentication and all record fragments. |
| `write_timeout_ms: ?u64 = null` | Budget for one complete outgoing handshake message, including transcript update, record encryption and all partial sends/fragments. |

A standalone ChangeCipherSpec read/write has its own budget. Interleaved TLS
1.3 compatibility CCS records share the enclosing message-read budget.
Each operation creates a child context once; progress and the socket's 10 ms
readiness slices do not restart its deadline. `null` adds no deadline and zero
expires before that operation performs I/O. These are logical context budgets,
not inherited `SO_RCVTIMEO`/`SO_SNDTIMEO` values. Set the parent's request deadline
to additionally bound the entire handshake. Parent deadlines are never mutated.

Pre-cancellation/expiry is checked before work, and context checks after
blocking boundaries take precedence over the completed I/O result. Concrete
TLS/provider/transport errors otherwise propagate unchanged. Configuration,
identity and provider-capability checks still precede transport access.
Providers remain synchronous: context checks do not forcibly interrupt an
arbitrarily blocking provider callback. On any handshake failure, discard the
connection/socket rather than retrying the same TLS stream.

The options/context are **not retained by the returned `Connection`**.
Embedders must explicitly use its existing context-aware application methods:

```zig
const io_context = httpx.io_context;
var shutdown: httpx.types.CancellationToken = .{};
var lifetime = io_context.IoContext.init(.{
    .external_cancel = &shutdown,
    .request_deadline = io_context.Deadline.afterMs(15_000),
});
var connection = try httpx.tls.acceptServerWithIo(
    allocator, socket, alpn_protocols, server_tls_config,
    .{ .context = &lifetime, .read_timeout_ms = 2_000, .write_timeout_ms = 2_000 },
);
defer connection.deinit();

var read_context = io_context.IoContext.init(.{
    .parent = &lifetime,
    .phase_deadline = io_context.Deadline.afterMs(2_000),
});
var bytes: [4096]u8 = undefined;
const n = try connection.readWithContext(&bytes, &read_context);
var write_context = io_context.IoContext.init(.{
    .parent = &lifetime,
    .phase_deadline = io_context.Deadline.afterMs(2_000),
});
try connection.writeAllWithContext(bytes[0..n], &write_context);
```

Reuse the same application child context across a logical read/write loop;
do not recreate deadlines per fragment. Keep the parent and external token
alive for active calls. Only cancellation signaling may race owner-thread I/O:
do not mutate parent deadlines, close/reuse its socket off-thread, or destroy
the configuration/provider until the operation has quiesced.

## ALPN Negotiation

The ALPN module provides protocol negotiation between client and server:

```zig
// Protocol detection
try std.testing.expect(alpn.isHttp2("h2"));
try std.testing.expect(alpn.isHttp3("h3"));
try std.testing.expect(alpn.isHttp1x("http/1.1"));
```

## Certificate Verification

The client passes the complete bounded peer chain, DNS/IP identity, current
time, scratch allocator, and selected signature adapter to `TrustProvider`.
The canonical policy owns path construction, anchor lookup and constraints;
the runtime extracts only the leaf public key and its PSS restrictions for
TLS proof-of-possession. It never accepts an arbitrary self-signed certificate
as a substitute for configured trust.

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

Provider refusal and certificate errors remain explicit. System-root support
and paired metadata hashing are subject to the separate canonical integration
and qualification described above.

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
| `x25519` | TLS 1.2/1.3, subject to selected-provider capabilities |
| `secp256r1` / `secp384r1` | TLS 1.2/1.3, subject to selected-provider capabilities |
| `x25519mlkem768` | Server-side TLS 1.3 hybrid, requires both provider operations; not offered by this client |

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
