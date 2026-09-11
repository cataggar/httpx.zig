# Standard trust policy

`src/tls/standard_trust.zig` implements the existing provider-neutral
`TrustProvider` contract. It owns roots and validates certificate paths; it is
not a TLS connection, a new primitive backend, or an OS chain-verification
wrapper. Shared TLS configuration, public exports, and handshake wiring are
separate integration work. This module alone does not qualify authenticated
Azure HTTPS or close issue #4.

## Owner and selected-signature seam

```zig
const standard_trust = @import("standard_trust.zig");
const cert_crypto = @import("cert_crypto.zig");

var roots = try standard_trust.TrustContext.init(allocator, io, .{
    .source = .system,
});
defer roots.deinit();

// `crypto` is the runtime's explicitly selected CryptoProvider.
var signatures = cert_crypto.CryptoCertificateVerifier.init(crypto);
try roots.provider().verifyPeer(.{
    .role = .server,
    .chain_der = peer_certificates, // leaf first, then unordered candidates
    .expected_identity = .{ .dns_name = "api.example.test" },
    .now_seconds = unix_seconds,
    .signature_verifier = signatures.verifier(),
    .scratch_allocator = scratch_allocator,
});
```

Keep both owners at stable addresses while their borrowed handles are in use.
`TrustContext` copies retained DER; initialization does not retain caller PEM,
DER-array, or file-path slices. Verification borrows all request input and
keeps no request state. The context is immutable after initialization, so
concurrent verification uses only each request's scratch allocator and
signature verifier. Those dependencies must themselves permit concurrent use.
Complete all calls before destroying the context.

`Options.source` accepts the existing `TrustSource`:

- `.system`: snapshot available platform root files at initialization.
- `.system_plus_custom`: require system discovery to succeed, then add custom
  anchors. Failure does **not** silently degrade to custom-only mode.
- `.custom_only`: exclusively use `.der_certificates`, `.pem_bytes`, or
  `.pem_file_path`. No system-store lookup occurs.
- `.provider`: borrow the supplied provider without taking ownership; its
  owner must outlive all users. `provider()` returns that borrowed handle.

Custom PEM accepts certificate blocks and surrounding ASCII whitespace, not
private keys, bag attributes, arbitrary text, or incomplete blocks. A named
relative PEM path is relative to the current working directory. Anchors must
be CA certificates within the supported profile, not arbitrary self-signed
leaf pins. An empty usable store fails with `TlsNoTrustAnchors`.

All non-anchor certificate signatures go through the supplied
`CertificateSignatureVerifier`, normally `CryptoCertificateVerifier` backed
by the selected `CryptoProvider`. Unsupported algorithms, invalid signatures,
and allocation failures are returned; there is no std/native verification
fallback. Root discovery uses stdlib parsing only to read root material, never
`Certificate.verify`, `Bundle.verify`, or native chain verification.

A configured anchor is trusted because of its source, **not** because it has
a valid self-signature. Anchor CA, validity, key-usage, EKU, path-length, and
supported-extension restrictions still apply. Its self-signature is not
verified, so an older anchor's SHA-1 self-signature does not authorize SHA-1
signatures on peer certificates.

## Policy profile

- Bounded DER framing; matching inner/outer signature AlgorithmIdentifiers;
  canonical serials, time encodings, key-usage bits, and duplicate-extension
  rejection. Supported directory strings are UTF8, PrintableString, IA5,
  BMPString, and UniversalString. Legacy TeletexString names are rejected.
- Exact DER issuer/subject name matching, with AKI/SKI key-ID consistency when
  both identifiers exist. No distinguished-name normalization or AIA fetching.
- Iterative path search with cycle avoidance and same-name alternate issuers.
  Peer-list order is not assumed to be a valid path.
- CA/basicConstraints and optional keyCertSign usage on every issuer,
  including the anchor. Path length counts non-self-issued intermediate CAs,
  excluding the leaf; self-issued key rollover is not a new trust source.
- Leaf digitalSignature usage when keyUsage is present. This profile is for
  signature-authenticated TLS, not static-RSA key-encipherment-only leaves.
  A CA certificate is not accepted as a TLS leaf.
- Server/client EKU restrictions on every path certificate where EKU is
  present; anyExtendedKeyUsage permits either role. Client authentication can
  omit a DNS/IP identity, but still requires the appropriate certificate path,
  time, and purpose. Application-specific client identity authorization remains
  the caller's responsibility.
- Inclusive `notBefore`/`notAfter` checks using the request's Unix time, with
  strict UTC/GeneralizedTime and calendar validation.
- SAN-only DNS/IP identity matching; **no CN fallback**. DNS is case-insensitive
  ASCII/A-label input, with one optional trailing dot on the requested name.
  Wildcards must occupy the whole leftmost label, match exactly one label, and
  have at least two suffix labels. Wildcard expansion over an `xn--` label is
  conservatively rejected. IDNA conversion is the caller's responsibility.
  IP identities compare the exact 4/16-byte iPAddress SAN, never a DNS string.
- Supported certificate signatures: RSA PKCS#1 SHA-256/384/512, P-256/SHA-256,
  P-384/SHA-384, and Ed25519 through the selected verifier. SHA-1/MD5 peer edges,
  RSA-PSS certificate AlgorithmIdentifiers, unsupported curves/key profiles,
  and unsupported algorithm parameters fail closed. RSA subject keys must
  have at least 2048 modulus bits; backend key-size limits still apply.

Unknown critical extensions fail. Name constraints, policy mappings, policy
constraints, and inhibitAnyPolicy currently fail even when incorrectly marked
noncritical; they are **not** silently ignored. Critical certificatePolicies
and other unsupported critical policy also fail. Noncritical policy IDs do
not confer EV or application-policy status. Noncritical unsupported SAN name
types are not used for DNS/IP identity matching; critical SAN containing such
types is rejected. Critical SKI/AKI is outside the supported profile.

There is no revocation/OCSP/CRL evaluation, CT policy, AIA download, automatic
root refresh, hostname lookup, or hidden network operation. The TLS owner
still must verify the handshake's proof of possession using the selected
primitive backend. Certificate path success does not replace that check.

## Bounds

`VerifyPeerRequest.limits` bounds peer count, individual/aggregate peer DER,
path depth (including leaf and anchor), and candidate issuer attempts.
The implementation uses an allocated iterative stack, not unbounded recursion.
It additionally caps extensions at 64, GeneralNames/attributes at 256, and
opaque constructed name nesting at eight levels.

Initialization defaults are 4,096 anchors, 256 KiB per certificate, 16 MiB
retained DER, 32 MiB input PEM, and 64 MiB peak stdlib discovery allocation.
All are configurable through `Options`; zero/inconsistent limits fail.
`load_time_seconds` selects a deterministic root-discovery snapshot time;
per-request verification always uses `VerifyPeerRequest.now_seconds`.
`anchorCount()` and `skipped_system_anchors` expose snapshot statistics.
Malformed/unsupported system anchors are excluded, never silently trusted;
malformed/unsupported custom anchors fail initialization.

## Platform qualification

| Target | Default system source | Custom anchors | Qualification here |
|---|---|---|---|
| aarch64 Linux | Zig stdlib standard CA-file/directory discovery | DER/PEM/file | Native Debug/ReleaseSafe local chain tests; local OS root-load test |
| x86_64 Linux | Same implementation | DER/PEM/file | Source/type compilation; native runtime still requires CI |
| FreeBSD/OpenBSD/NetBSD/DragonFly/illumos/Haiku/Serenity | Zig stdlib designated CA file | DER/PEM/file | Implemented file-store dispatch; not runtime-qualified here |
| macOS / Mac Catalyst | Explicit `TlsTrustStoreLoadFailed` | DER/PEM/file or supplied provider | macOS source/type compilation only |
| Windows | Explicit `TlsTrustStoreLoadFailed` | DER/PEM/file or supplied provider | Windows source/type compilation only |
| Other targets | Explicit `TlsTrustStoreLoadFailed` | Where the target supports required Zig allocation/IO | Not qualified |

macOS's stdlib keychain export includes `System.keychain` certificates without
effective per-certificate trust/distrust settings. Windows ROOT export omits
purpose/distrust metadata; delegating to native chain verification would also
perform certificate signatures outside the selected primitive provider.
Neither export is represented as complete production OS trust here. Proper
platform trust metadata/root selection, implemented without hidden signature
fallback, remains a distinct requirement for those defaults. Custom-only
trust is not labeled system trust.

File-store discovery inherits Zig's snapshot behavior, including exclusion of
expired/unrecognized certificates and subject-name deduplication. A skipped
anchor or unsupported chain profile can reject an otherwise valid deployment.
No live public endpoint, Windows/macOS native runtime, or SymCrypt-native
handshake qualification is claimed by these local tests.

## Local validation

Run from the package root, keeping caches inside this worktree:

```sh
zig test src/tls/standard_trust_test.zig --cache-dir .zig-cache/trust-policy
zig test src/tls/standard_trust_test.zig --cache-dir .zig-cache/trust-policy -O ReleaseSafe
zig test src/tls/standard_trust_system_test.zig --cache-dir .zig-cache/trust-policy
```

`trust_fixtures.zig` creates deterministic local Ed25519 and P-256 chains in
pure Zig. `fixtures/trust/root_ed25519.pem` is the reproducible named file
fixture, containing only a test root certificate. Fixture code is not imported
by the production owner. Tests cover positive chains, alternate issuers,
unknown roots, invalid signatures, critical policy, CA/usage/purpose/time
failures, SAN/IP/wildcard policy, self-issued rollover, cycles, bounded search,
input limits, copied ownership, concurrent verification, allocation failures,
and a selected provider that deliberately refuses signature verification.
