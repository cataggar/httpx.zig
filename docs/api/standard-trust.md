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
| Windows | Crypt32 ROOT/Disallowed plus bounded local CTL metadata; unsupported forms fail closed | DER/PEM/file or supplied provider | Strict profile implemented; source/link checks, native execution still pending |
| Other targets, including Mac Catalyst | Explicit `TlsTrustStoreLoadFailed` | Where the target supports required Zig allocation/IO | Not qualified |

Windows links Crypt32. macOS links Security and CoreFoundation. These are
platform system libraries accessed through Zig declarations: no C source,
shim, third-party TLS/crypto library, or OS certificate-signature fallback.

macOS builds require an Apple SDK providing those frameworks, including when
cross-compiling. Pass its root with `--sysroot /path/to/MacOSX.sdk` when selecting
an explicit macOS target. The build uses that SDK's framework and library search
paths. CI discovers the installed SDK with `xcrun` and supplies it for both macOS
architectures; it does not omit the framework links or vendor an SDK.

Linux/custom policy remains pure Zig, with no added Linux native linkage.
Downstream build integration must propagate the same platform links.

### Windows snapshot and CTL profile

Read-only, existing logical ROOT and Disallowed stores are inspected in current
user and local machine scope. Duplicate restrictions intersect; explicit
distrust is applied to selected leaf/intermediate/anchor certificates, including
custom duplicates in `system_plus_custom`. DER EKU and context EKU properties
are intersected by `CertGetEnhancedKeyUsage`; absent usage and explicitly empty
(disabled) usage remain distinct.

Disallowed EKU and time properties are retained. Time cutoffs conservatively
reject **all** use at/after the earliest cutoff, rather than grandfathering
older issuance. Unsupported root-program certificate policies, name
constraints, chain policies, and not-before issuance/purpose properties
(`CERT_NOT_BEFORE_FILETIME_PROP_ID` 126 and
`CERT_NOT_BEFORE_ENHKEY_USAGE_PROP_ID` 127) exclude the affected certificate. Property
errors, malformed values, and size races fail initialization.

The loader enumerates local CTLs and reads cached AuthRoot/Disallowed values
using Zig's existing read-only NT registry APIs. `CertCreateCTLContext` decodes
a copied, non-persisted CMS context; bounded pure-Zig policy parsing consumes
its CTL_INFO content. No CMS signature/chain verification or root retrieval is
requested. Metadata authority comes from the local OS store/cache, **not** an
arbitrary downloaded CMS object. Test-only unsigned envelopes exercise decoding
and do not establish trust.

The existing whole-certificate CTL profile uses SHA-1/256/384/512 identifiers,
with additional SHA-256 consistency checks when present. SHA-1 requires explicit
binding permission and selected-provider capability/deployment approval.
The dedicated Disallowed identity family below is separate from that profile.
Bare MD5, other property selectors, unknown attributes, multiple values, and
unsupported CTL-wide extensions still fail closed. AuthRoot's bounded
friendly-name/key-ID/subject-name locator fields are not alternate matching keys.
Purpose, disable-time, and unsupported issuance/policy restrictions are
retained rather than discarded.

#### Documented Disallowed deny identities

Only a **Disallowed** CTL whose SubjectAlgorithm is
`szOID_DISALLOWED_HASH` (`1.3.6.1.4.1.311.10.11.15`, absent or NULL parameters)
uses this additional family. The
[pinned Microsoft SDK](https://github.com/microsoft/win32metadata/blob/1bfb76db1c360653bdcb56512af0fdf987aceab8/generation/WinSDK/RecompiledIdlHeaders/um/wincrypt.h#L9440-L9482)
aliases this identifier to property 15 and names properties 15 and 25 as
Disallowed hashes. The
[property contract](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatecontextproperty)
and [`CryptHashToBeSigned`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-crypthashtobesigned)
define the two identities:

- **P15:** the signature-algorithm-selected hash of the **exact encoded
  TBSCertificate**, including its SEQUENCE tag and length.
- **P25:** **MD5 of raw subjectPublicKey BIT STRING payload bytes**, excluding
  the unused-bit-count octet, BIT STRING framing, and SPKI AlgorithmIdentifier.
  It is not MD5 of the certificate, encoded SPKI, or signature bytes.

An exact full-byte **and length** match to **either** identity denies use.
Every required identity must be calculated successfully before a nonmatch can
allow use, including for an empty list. An already established deny may return
early. A failed hash, denied permission, unsupported algorithm/parameter/key
encoding, malformed DER, or allocation failure is never a nonmatch.
Identifier widths are only bounded to supported digest output lengths
(16/20/32/48/64); they do **not** select algorithms or domains. Identifiers are
not truncated, split, concatenated, or silently dropped. All data is copied and
a CTL is published only after its entire metadata validates.

Inner and outer signature AlgorithmIdentifiers must have identical canonical
DER. Supported metadata mappings are:

| Signature AlgorithmIdentifier | Parameters | P15 hash |
| --- | --- | --- |
| RSA PKCS#1 MD5 / SHA-1 | Required NULL | MD5 / SHA-1 |
| RSA PKCS#1 SHA-256/384/512 | NULL or absent | Corresponding SHA-2 |
| ECDSA SHA-256 / SHA-384 | Absent | SHA-256 / SHA-384 |
| RSA-PSS | Present empty SEQUENCE | SHA-1 defaults |
| RSA-PSS SHA-256/384/512 | Explicit matching hash and MGF1 hash, digest-sized salt; omitted default trailer | Corresponding SHA-2 |

This intentionally narrow PSS subset rejects absent parameters, mismatched
MGF/hash, other salts/trailers, and explicit default-field encodings outside
the table. It is not full RFC-PSS acceptance. These are **metadata mappings**:
they do not enable MD5/SHA-1 signatures or expand the certificate-edge signature
profile (which still rejects RSA-PSS edges).
[RFC 3279 §2.2.1](https://www.rfc-editor.org/rfc/rfc3279#section-2.2.1)
defines the legacy RSA mappings/NULL parameters;
[RFC 4055 §§3.1 and 5](https://www.rfc-editor.org/rfc/rfc4055#section-3.1)
defines PSS hash selection and the SHA-2 RSA mappings.
[RFC 5758 §3.2](https://www.rfc-editor.org/rfc/rfc5758#section-3.2)
defines the ECDSA SHA-2 mappings and absent parameters.

Existing strict RSA (at least 2048 bits), P-256, P-384, and Ed25519 **subject-key**
framing is reused without normalizing the key bytes; the native
[`CRYPT_BIT_BLOB`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_bit_blob)
contract represents the key bits as bytes, separately from the unused-bit
count. Other key profiles and
nonzero unused bits reject. Ed25519 **issuer signatures** have no supported P15
mapping: with these Windows system restrictions, an Ed25519-signed selected
certificate fails closed even if P25 did not match. `custom_only` neither loads
nor applies system restrictions and retains its separate Ed25519 support.
`system_plus_custom` does not exempt custom anchors or duplicate certificates.

The [bounded synthetic native comparisons](https://github.com/cataggar/httpx.zig/actions/runs/34790621907)
and [supplemental ARM64 runtime execution](https://github.com/cataggar/httpx.zig/actions/runs/34792012714)
established the byte domains for P-256/RSA subject encodings, ECDSA SHA-256/384,
explicit SHA-256 PSS, empty-default PSS, and the MD5 AlgorithmIdentifier control.
RSA SHA-1/SHA-2 and SHA-384/512 PSS mappings are justified by the contracts above,
not additional native fixtures. P-384/Ed25519 subject framing is covered by the
existing DER/key parsers, not a claim of additional native property comparisons.
Generic `CertFindSubjectInCTL` ANY lookup only establishes opaque equality;
its concatenation controls do **not** establish compound identifiers. This
profile claims neither undocumented compound-format support nor full private
Windows chain-policy equivalence. It uses no native hashing or verification
fallback and does not broaden AuthRoot or any trust-grant profile.

#### AuthRoot CT log catalog

One noncritical AuthRoot extension is recognized:
`szOID_CERT_LOG_LIST_EXT` (`1.3.6.1.4.1.311.10.3.52`). Microsoft's
[public SDK header](https://github.com/microsoft/win32metadata/blob/1bfb76db1c360653bdcb56512af0fdf987aceab8/generation/WinSDK/RecompiledIdlHeaders/um/wincrypt.h#L3586-L3587)
describes it as containing “the list of logging servers for CT”. The published
[crt.sh AuthRoot parser](https://github.com/crtsh/root_programs/blob/4b23f373d0e4dad72a039719c889777a0698e63c/microsoft_authroot/microsoft_authroot.go#L113-L135)
decodes an integer-sequence header followed by SubjectPublicKeyInfo sequences;
its [extension handling](https://github.com/crtsh/root_programs/blob/4b23f373d0e4dad72a039719c889777a0698e63c/microsoft_authroot/microsoft_authroot.go#L280-L306)
updates **CT-log inclusion**, separately from certificate/root-trust-purpose
processing. These are log keys, not root certificates, CTL subject identifiers,
or an alternate issuer/anchor source. They have no authority in this engine's
certificate-path policy, which does not implement CT.

The [native structural observation](https://github.com/cataggar/httpx.zig/actions/runs/34775212836)
identified this OID and a complete 50-sequence catalog, with three single-byte
INTEGER fields in its first sequence. It did not establish the fields' values
or meanings. The public parser itself labels that header “Version?” rather than
defining its semantics; this implementation does **not** claim a normative
Microsoft ASN.1 specification or interpret those integers as version policy,
permissions, dates, flags, or CT authorization.

The supported, non-authorizing profile validates three canonical nonnegative
INTEGERs no larger than `u32`, then zero to 256 structurally framed RSA PKCS#1,
P-256, or P-384 SPKIs. A key is at most 4 KiB; the extension value obeys the
64 KiB property bound. It consumes every byte of the catalog, Extension,
Extensions sequence, explicit `[0]` wrapper, and enclosing CTL. Catalog keys and
parameters are not retained, hashed, used to verify signatures/SCTs, installed,
or consulted by path validation. Structural acceptance is not cryptographic
validation of the log keys or a promise to enforce a CT-log policy.

Only this exact AuthRoot profile is accepted, with the DER default `critical`
field omitted. Duplicate extensions, explicit critical/false encodings, unknown
extensions (including noncritical ones), other list kinds, unsupported keys or
header shapes, malformed/trailing DER, and exhausted bounds fail closed.
There is no blanket “ignore noncritical” rule. The catalog cannot erase list
freshness, usage, membership, anchor provenance, subject restrictions, or the
empty-104 exclusion below. A whole CTL is published only after global metadata
validation succeeds; failures retain no partial list or borrowed input.
Native Windows qualification of this new profile remains a separate gate.

#### Per-certificate restrictions and provenance

Native Windows runs have encountered an **explicit empty** AuthRoot attribute
104. The [native conformance run](https://github.com/cataggar/httpx.zig/actions/runs/34769265281)
observed a **present zero-length property**, not absence, after applying
Microsoft's
[`CertSetCertificateContextPropertiesFromCTLEntry` contract](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certsetcertificatecontextpropertiesfromctlentry)
to a fresh, unattached leaf context. Omitting 104 retained the existing
eight-byte property; empty 104 replaced its value without removing the property
or independent property 128. The API documentation does not establish the
empty state's authorization meaning.

This profile therefore retains empty 104 as an **unsupported per-certificate
restriction**, in both CTL and native property snapshots. A matching subject is
ineligible at every verification time and for either TLS role, including custom
duplicates; unrelated roots can still be loaded. This is not a guessed
timestamp, deletion marker, or permission to remove other native/CTL
restrictions. Disallowed-list membership remains independently prohibitive.
Absent 104 adds no such restriction; an eight-byte zero FILETIME remains an
actual encoded cutoff. Nonempty 104 and all 128 values still require exactly
eight bytes; apart from the explicit empty-126 containment below, other empty,
malformed, and unsupported forms retain their existing fail-closed behavior.

The native fixture asserts these structural observations without opening a
store, installing certificates, modifying roots, or verifying a chain. This
conservative exclusion can reject certificates that Windows accepts: full
Windows authorization semantics for empty 104 remain unimplemented, and a
successful snapshot load does not establish platform or public-TLS equivalence.

The [bounded native property observation](https://github.com/cataggar/httpx.zig/actions/runs/34815807373)
also found a successful initial query for property **126** with zero required
bytes and a 65,536-byte bound. The
[pinned SDK definition](https://github.com/microsoft/win32metadata/blob/1bfb76db1c360653bdcb56512af0fdf987aceab8/generation/WinSDK/RecompiledIdlHeaders/um/wincrypt.h#L9370)
names this property `CERT_NOT_BEFORE_FILETIME_PROP_ID`, not a root-program
certificate-policy property. The observation alone does not establish native
authorization semantics.

This profile conservatively retains **present-empty 126 as an unsupported
certificate restriction**, just like nonempty 126. It is not absence, a cleared
restriction, FILETIME zero, an interpreted timestamp, or unrestricted trust.
The affected certificate is ineligible at every path position and time, for
either TLS role, including when it duplicates a custom anchor; unrelated roots
remain available. Absence remains distinct. No timestamp is synthesized from
either empty or nonempty 126, and an absent duplicate does not erase an
already retained restriction.

An empty initial result is accepted only for the explicitly supported 104 and
126 cases, with a nonzero bound. The second query must still succeed and return
exactly the original size, including zero; disappearance, query failure, size
changes, exceeded bounds, and allocation failure abort loading. Empty 128, 83,
84, 105, 127, other unknown empty properties, and malformed values retain their
previous rejection rules. This change does not generalize empty-property
acceptance, modify CTL selectors, or claim Windows chain-engine equivalence.

Certificates found in the local AuthRoot cache are marked as program material
without adding anchors. System anchors marked this way must appear in every
applicable current AuthRoot list. Missing/expired program metadata fails closed.
Explicit custom anchors need not belong to Microsoft's root program, but
applicable distrust and other restrictions still apply to custom duplicates.
List times are evaluated against each request's current time, with no hidden
cache refresh. This can reject stale or unsupported platform state; full OS
chain-engine parity and general Windows native qualification are not claimed.

`metadata_digest.zig` and `policy_binding.zig` carry identifier hashing without
changing ABI-v1 request or existing vtable layouts. The trust implementation
does not request or use identifier digests while loading roots: lookups occur
only during bound verification, so
immutable root ownership remains independent of the primitive backend.

The paired view accepts only its exact signature context/vtable, and rejects
different signature/digest contexts. The runtime must obtain both operations
from one selected-provider adapter and pass the binding's signature handle.
Roots, adapter/provider, and the stable binding must outlive pooled sessions
and active calls. Hash input/output/scratch are borrowed per call; temporary
hash state must be destroyed on every exit. Outputs have exactly the selected
digest length and are cleared on every failure. Binding
`allow_sha1_identifiers` defaults false, independently of native-provider
capability/deployment approval. Identifier hashing never enables SHA-1
signatures, HMAC, HKDF or PRF, creates an anchor, or permits a primitive fallback.

The ABI-2 metadata foundation exposes default-off
`allow_md5_identifiers`, independently gated by the selected backend's MD5
deployment permission. MD5 remains unavailable to keyed operations and
signatures. The documented Disallowed family requires this opt-in even when
P15 uses SHA-2, because P25 is also required before allowing. With the standard
backend, use `StandardProvider.initWithOptions(...,
.{ .allow_md5_identifier_hash = true })` and bind with
`.{ .allow_md5_identifiers = true, .allow_sha1_identifiers = true }` when the
snapshot requires both legacy identifiers. Neither permission enables the
other; primitive ABI-1 providers cannot satisfy required MD5 and are rejected
before raw MD5 dispatch. The per-certificate cache keys on **algorithm and
byte domain** (whole DER, TBS DER, raw key), including separate MD5 values,
and is discarded between operations.
See [metadata-only digests](./tls.md#metadata-only-certificate-digests).

The canonical owner now exposes
`roots.bind(adapter_pointer, metadata_digest.Options) !PolicyBinding`.
The adapter supplies `verifier()` and `metadataHasher(options)` from the same
selected provider. A new per-handshake adapter is not interchangeable with an
older binding, even when both wrap the same backend: create the binding and
verifier together, or use the binding's existing `signatureVerifier()` handle.
Short-lived paired views are valid for synchronous verification only when no
pooled object retains their handles. Stored views require stable owners for the
entire pool lifetime. Caller-supplied ABI-v1 trust providers remain borrowed and
are forwarded their unchanged request. Do not mutate or retarget binding or
adapter/provider configuration while borrowed views are in use.

Private fingerprint-policy plumbing copies bounded lists, intersects duplicate
restrictions, checks list times against the request's current time, and caches
digests only on the verification stack. A secondary SHA-256 mismatch rejects
the certificate rather than dropping its restriction. Hashes are evaluated on
selected path certificates through the binding; they never add anchor entries.
The current limits are 16 MiB per encoded/decoded CTL, eight lists, 16,384 total
records, and 64 attributes per record. Missing digest
support fails closed; hash allocation failures remain `OutOfMemory`. Hermetic
tests exercise this plumbing with real selected standard-provider hashes and
signatures, and verify CTL parsing/ownership/bounds. Shared production adapter
and runtime wiring remain separate integration work. Direct native policy
tests use a test-only adapter implementing the same contract, not a claim that
production HTTPX TLS calls are already wired.

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
