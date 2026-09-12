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

- `.system`: snapshot available platform root files or read-only OS trust
  metadata at initialization.
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
leaf pins. An empty parsed CA store fails with `TlsNoTrustAnchors`; platform
metadata can further restrict which candidates are eligible for a request.

All non-anchor certificate signatures go through the supplied
`CertificateSignatureVerifier`, normally `CryptoCertificateVerifier` backed
by the selected `CryptoProvider`. Unsupported algorithms, invalid signatures,
and allocation failures are returned; there is no std/native verification
fallback. Where stdlib root-file parsing is used, it is discovery only.
Neither `Certificate.verify`, `Bundle.verify`, nor native chain verification
is used.

A configured anchor is trusted because of its source, **not** because it has
a valid self-signature. Anchor CA, validity, key-usage, EKU, path-length, and
supported-extension restrictions still apply. Normally its self-signature
is not verified, so an older anchor's SHA-1 self-signature does not authorize
SHA-1 signatures on peer certificates. A macOS `trustRoot` setting additionally
requires a self-issued certificate and a valid self-signature through the
selected verifier; this intentionally excludes SHA-1 `trustRoot` self-signatures.
This extra classification check does not itself establish trust.

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
anchor DER, 32 MiB input PEM, and 64 MiB peak Zig-managed discovery allocation.
Native snapshots separately cap 8,192 system certificates (including distrust
entries), 16 MiB metadata-associated DER, 64 rules per certificate/domain,
64 KiB per Windows property, and 254 ASCII bytes per hostname constraint.
The native snapshot retains its own DER and rule copies. OS-owned allocations
inside Crypt32/CoreFoundation are not governed by a Zig allocator; counts and
output sizes are checked before copying. The discovery budget does not include
the separately bounded final anchor copies.
`Options` configures the anchor, certificate-count, DER, PEM, and discovery
budgets; zero/inconsistent limits fail. Rule/property/hostname caps are fixed
implementation limits.
`load_time_seconds` selects the root-file loader's snapshot time. Native
snapshots read current OS state; all verification validity/cutoff checks use
`VerifyPeerRequest.now_seconds`.
`anchorCount()` and `skipped_system_anchors` expose snapshot statistics.
The count is anchor candidates, not an assertion of eligibility for a given
purpose/identity; the skipped count covers DER/profile parsing exclusions.
Malformed/unsupported system anchors are excluded, never silently trusted;
malformed/unsupported custom anchors fail initialization.

## Platform qualification

| Target | Default system source | Custom anchors | Qualification here |
|---|---|---|---|
| aarch64 Linux | Zig stdlib standard CA-file/directory discovery | DER/PEM/file | Native Debug/ReleaseSafe local chain tests; local OS root-load test |
| x86_64 Linux | Same implementation | DER/PEM/file | Source/type compilation; native runtime still requires CI |
| FreeBSD/OpenBSD/NetBSD/DragonFly/illumos/Haiku/Serenity | Zig stdlib designated CA file | DER/PEM/file | Implemented file-store dispatch; not runtime-qualified here |
| macOS desktop | Security/CoreFoundation anchor and trust-settings snapshot | DER/PEM/file or supplied provider | Implemented; source/type compilation here; native CI required |
| Windows | Crypt32 ROOT/Disallowed metadata snapshot, **blocked when unsupported CTLs exist** | DER/PEM/file or supplied provider | Partial system profile; source/link compilation, not native runtime qualification |
| Other targets, including Mac Catalyst | Explicit `TlsTrustStoreLoadFailed` | Where the target supports required Zig allocation/IO | Not qualified |

Windows links Crypt32. macOS links Security and CoreFoundation. These are
platform system libraries accessed through Zig declarations: no C source,
shim, third-party TLS/crypto library, or OS certificate-signature fallback.
Linux/custom policy remains pure Zig, with no added Linux native linkage.
Downstream build integration must propagate the same platform links.

### Windows snapshot and pending CTL support

Read-only, existing logical ROOT and Disallowed stores are inspected in current
user and local machine scope. Duplicate restrictions intersect; explicit
distrust is applied to selected leaf/intermediate/anchor certificates, including
custom duplicates in `system_plus_custom`. DER EKU and context EKU properties
are intersected by `CertGetEnhancedKeyUsage`; absent usage and explicitly empty
(disabled) usage remain distinct.

Disallowed EKU and time properties are retained. Time cutoffs conservatively
reject **all** use at/after the earliest cutoff, rather than grandfathering
older issuance. Unsupported root-program certificate policies, name
constraints, and chain policies exclude the affected certificate. Property
errors, malformed values, and size races fail initialization.

Hash-only CTLs are **not yet implemented**. CTLs found in logical stores, or
cached AuthRoot/Disallowed CTL values detected through existing read-only Zig
NT registry bindings, fail initialization. This can block ordinary provisioned
Windows machines; general Windows system trust is not claimed complete.
Completing it needs bounded CTL interpretation and an approved fingerprint
matching seam: ABI-v1 currently exposes signatures, not hashes. Detection is
not a permanent OS/API blocker and must not be removed to make CI green.
The loader never downloads roots or invokes a native chain engine.

### macOS snapshot and strict projection

`SecTrustCopyAnchorCertificates` supplies baseline anchors; public trust-settings
APIs supply user, administrator, and system records. Domain priority is user
before administrator before system. Absence differs from an empty settings
array (`trustRoot`). `deny`, `unspecified`, `trustRoot`, and `trustAsRoot` are
distinct; non-CA leaf pinning remains outside this profile.

Supported rules constrain SSL server/client purpose, certificate versus data
signing key use, and exact DNS/IP identity. Rules are alternatives, with deny
winning within a domain. An unspecified result cannot establish trust or mask
a lower-domain deny. A present but nonmatching higher-domain record does not
inherit a broader grant from below. This is intentionally stricter than relying
on unspecified platform fallback behavior.

Application code-identity constraints, allowed-error waivers, non-SSL policies,
unknown rule/property keys, and unsupported identity forms fail closed rather
than becoming unrestricted trust. All retained metadata is copied; CF objects
are released on success and failure. Discovery is an immutable best-effort
snapshot, not an atomic OS trust-settings transaction. Reinitialize after trust
settings change. Full trustd/OS chain-policy parity is not claimed.

File-store discovery inherits Zig's snapshot behavior, including exclusion of
expired/unrecognized certificates and subject-name deduplication. A skipped
anchor or unsupported chain profile can reject an otherwise valid deployment.
No live public endpoint, Windows/macOS native runtime, or SymCrypt-native
handshake qualification is claimed by these local tests.

## Local validation

Run from the package root, keeping caches inside this worktree. Direct commands
below are for Linux; use the build targets on Windows/macOS to supply OS links:

```sh
zig test src/tls/standard_trust_test.zig --cache-dir .zig-cache/trust-policy
zig test src/tls/standard_trust_test.zig --cache-dir .zig-cache/trust-policy -O ReleaseSafe
zig test src/tls/standard_trust_system_test.zig --cache-dir .zig-cache/trust-policy
zig build test-tls-standard-trust test-tls-system-trust --summary all
zig build test-tls-standard-trust test-tls-system-trust -Doptimize=ReleaseSafe --summary all
```

`test-tls-standard-trust` includes hermetic platform metadata cases and
process-local native API fixtures on their own OS. `test-tls-system-trust`
reads the installed store; it never changes it. The dedicated native CI
workflow runs both in Debug/ReleaseSafe on hosted Linux, Windows, and macOS.
It has not been run remotely as part of local implementation. Unsupported
system state fails that qualification gate, rather than being skipped.
No mutable user/machine trust-store fixture or hidden setup command is included.
Actual domain/store mutation tests require a separately approved, explicitly
guarded disposable-runner fixture; never run them on a shared development host.

`trust_fixtures.zig` creates deterministic local Ed25519 and P-256 chains in
pure Zig. `fixtures/trust/root_ed25519.pem` is the reproducible named file
fixture, containing only a test root certificate. Fixture code is not imported
by the production owner. Tests cover positive chains, alternate issuers,
unknown roots, invalid signatures, critical policy, CA/usage/purpose/time
failures, SAN/IP/wildcard policy, self-issued rollover, cycles, bounded search,
input limits, copied ownership, concurrent verification, allocation failures,
and a selected provider that deliberately refuses signature verification.
