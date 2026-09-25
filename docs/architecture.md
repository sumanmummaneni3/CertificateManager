<!--
Decision records, newest first. Each record is a D-numbered blueprint: findings first, then the
design, then what it deliberately does not do. Append-only — never delete or renumber a record;
strike through and re-date if superseded. This repo's D-numbers are its own sequence, separate
from Monitor360's (see CLAUDE.md's Scope note).

Next free number: D14 (D5–D7 and D9–D13 are backlog rows; D5–D7 filed alongside D1–D4, D12–D13 by
D8's design audit — the D-number sequence is shared between architecture.md and backlog.md, per
Monitor360's own convention).
-->

## D8 — Amendments to D1–D4 before implementation (gap review, 2026-09-25)

**Status:** approved 2026-09-25 (the user reviewed the gap table this record answers and asked for
every row to be implemented). **Implemented 2026-09-25, with D1–D4, in the same session: 72 new unit
tests, 85 in the suite, all passing. Built, not field-verified:** acceptance gate items 2 and 4
below are met and items 1 and 3 are open. ~~No separate reviewer or architect-audit pass was run.~~
*(2026-09-25, later: Reviewer PASS on commit `d4201ac`. Architect design audit of `d4201ac`: **not
certified.** One DESIGN_VIOLATION, routed to the Developer: a host:port with some addresses
unreachable is recorded as a `ver` `OK` row, see "Findings and reports" below. Two blueprint gaps
filed as backlog D12 and D13.)*
*(2026-09-25, re-audit of the uncommitted fix on top of `d4201ac`: **CERTIFIED as built.** The
violation is fixed: each unreachable address has its own `ver` `ERROR` row, which counts as a failed
check. D12 and D13 are fixed as filed. 89 unit tests, all passing. Still **not field-verified**:
acceptance gate items 1 and 3 remain open (backlog D11), and no real crt.sh answer has ever been
parsed.)*
**Amends:** D1, D2, D3, D4. Where this record and D1–D4 disagree,
**this record wins**; D1–D4 are left unedited as history.

### Findings

- **F1.** D2's `MISSING_INTERMEDIATE`/`AIA_ONLY_COMPLETION` rule ("the last served cert's issuer is
  not a subject within the served chain") fires on **every correctly configured server**: a correct
  server never sends its root, so a leaf + intermediate chain never terminates within what was
  served. A chain's completeness cannot be judged without trust anchors.
- **F2.** D3's `UNOBSERVED_ISSUANCE` compares every CT issuance ever logged against what is served
  *right now*. A one-shot CLI has no served history, so every expired prior renewal (about six a
  year for a Let's Encrypt name) would be a Medium finding.
- **F3.** D3 pulls CT per CSV row and cross-checks against that row's handshakes only. With rows
  `www.a.com` and `api.a.com`, the `api` certificate appears as unobserved under the `www` row.
  CT-01 is per registrable domain, including subdomains and wildcards.
- **F4.** D2 rated an expired certificate Critical at any chain position. ALR-02 rates "served
  certificate expired" Critical but chain defects (including expired cross-signs) Medium.
- **F5.** D2's `WEAK_SIGNATURE` checked self-signed roots, whose own signature no client verifies.
- **F6.** D4's `CAA_NO_ACCOUNT_BINDING`/`CAA_NO_METHOD_BINDING` fired on `issue ";"`, which
  forbids all issuance, the strictest setting there is.
- **F7.** D4's 2-label climb floor is not RFC 8659. RFC 8659 §3 climbs every label up to (not
  including) the root, and that is what CAs do; querying `co.uk` or `uk` is harmless. The public
  suffix list D4 said was missing is not needed for CAA at all.
- **F8.** D1's `Finding` carried no evidence, no observation time and no remediation; RPT-01
  requires all three. D1 also produced no report template, which the Phase 0 bullet lists.
- **F9.** crt.sh returned HTTP 502 to four requests on 2026-09-25 while this record was written.
  The user's decision: crt.sh stays the only CT source and **its failure is reported exactly as
  received** (status code and body), not swallowed and not replaced by a fallback provider.
- **F10.** crt.sh's JSON has no fingerprint, and a precertificate's DER differs from the final
  certificate's (the poison extension), so a SHA-256 match is only possible against final-cert
  entries and costs one extra request each.
- **F11.** CAA-01 needs the DNS header's AD bit. dnsjava's `Lookup` does not expose the response
  header, so D4's "read the AD bit off `Lookup`" is not implementable as written.
- **F13 (found by the first live run, 2026-09-25, after implementation).** example.com serves
  leaf → intermediate → *SSL.com TLS ECC Root CA 2022* cross-signed by Comodo *AAA Certificate
  Services*. The first implementation walked the served chain to its end and asked the anchors about
  the last certificate. Debian's JDK trust store holds SSL.com's root but no longer holds AAA, so a
  correct chain was reported `MISSING_INTERMEDIATE` on all three addresses. **The walk must stop at
  the first certificate that is an anchor or is signed by one**, as a path builder does. Fixed and
  covered by `ChainAnalyzerTest.stopsAtFirstAnchor`. The result still depends on the running JDK's
  trust store (backlog D9).
- **F12.** dnsjava 3.6.5 (BSD-3-Clause, confirmed from the published POM 2026-09-25) depends on
  `slf4j-api` at runtime; without a binding it prints a "no providers" warning on every run.

### Design (per gap row)

**CSV (INT-04, amends D1).** Header row **required**, columns matched by name, case-insensitive:
`host` (required), `port` (default 443), `domain` (registrable domain, optional), `owner`
(optional), `tags` (optional, `;`-separated `key=value`). Fields may be double-quoted
(RFC 4180 style: `""` escapes a quote), since Excel quotes any cell containing a comma. A bad row
goes to `RowError` and is skipped. Duplicate `(host, port)` rows are merged (NFR-03: one handshake
per address per target per run) and reported as a row warning.

**Run basis (RPT-02, amends D1).** `-audit` requires `--requester <name>` and
`--basis <OWN|CONSENT|PUBLIC_PROSPECT>`. Both are written to the JSON header and appended to
`~/.certmgr/logs/audit-runs.log` (timestamp, requester, basis, CSV path, target count). No port is
ever contacted other than the CSV's `port` column.

**Served state (VER-01/02, CHN-01, amends D2).** As D2, plus: `ServedStateProber` takes a resolver
and a handshake function as constructor arguments so tests need no network. Every observation
records `observedAt`. The JSON holds a run-wide certificate table keyed by SHA-256 and each
observation holds the ordered list of fingerprints (CHN-01).

**Chain defects (CHN-03, amends D2).** New `TrustAnchors`: the JDK default trust store
(`TrustManagerFactory.init((KeyStore) null)`), matched by subject DN **and** a successful
`verify(anchor.getPublicKey())`. The chain terminates when the last served certificate is
self-signed, or is signed by an anchor. Otherwise:
- AIA caIssuers URL present → `AIA_ONLY_COMPLETION` (browsers fetch the issuer; most non-browser
  clients, including Java, fail). This is the usual shape of a missing intermediate on the public
  web and is expected to be far more common than the next one.
- no AIA → `MISSING_INTERMEDIATE`. The detail says the chain does not reach a *public* anchor, so a
  private-PKI host reads as "anchor unknown to the audit", not as proven broken.

Expiry splits in two: `EXPIRED_SERVED_CERT` (position 0, **Critical**) and `EXPIRED_IN_CHAIN`
(position ≥ 1, **Medium**). `WEAK_SIGNATURE` skips self-signed certificates; `WEAK_KEY` checks every
position. `ROOT_INCLUDED` requires chain length > 1.

**Chain change (CHN-02, amends D2).** `CHAIN_CHANGED` is **High** and its detail lists removed and
added certificates (subject + SHA-256). Baseline matching is by `(host, port, leafSha256)`, not by
address: a current observation is compared with every baseline observation for the same host:port
that served the same leaf, and raises only if none of them had the same chain hash. No baseline, or
no baseline entry for that host:port, is recorded as coverage `NOT_CHECKED` for `chn02`, never as a
pass.

**CT scope (CT-01, amends D3).** CT runs once per distinct **CT domain**: the row's `domain` column,
or, when blank, the row's `host` with coverage scope `HOST_ONLY` recorded in the export (no public
suffix list; backlog D5 re-scoped). Two queries per domain, `q=<domain>` and `q=%.<domain>`,
unioned and deduplicated. Every request carries User-Agent
`CertificateManager-Audit/<version> (+https://github.com/sumanmummaneni3/CertificateManager)`
(NFR-03). Responses are cached under `~/.certmgr/ct-cache/` keyed by URL hash, with the fetch time;
`--ct-cache-ttl <hours>` (default 6, 0 disables). Rate gate: at least 12.5 s between live requests,
shared across the run.

**CT errors (F9).** One retry, then the domain's `ct` check is `ERROR` with the message **as
received**: `crt.sh HTTP 502 for <url> (attempt 2 of 2): <first 200 chars of body, whitespace
collapsed>`, or the exception class and message for an I/O failure, or `crt.sh returned non-JSON
body: …`. No fallback provider. A CT error never produces zero findings silently: the coverage CSV
and the Markdown report both name the domain and the error.

**Unobserved issuance (CT-02/03, amends D3).** Reconcile on `(issuer, serial)`, not serial alone.
*(Implementation note, 2026-09-25: the cross-check is against every leaf served **anywhere in the
run**, not only hosts under the CT domain, because a multi-SAN certificate for this domain may be
served on a host listed under another. When no host under the domain was reachable, CT-03 is
recorded as `NOT_CHECKED` for that domain rather than flagging every issuance. crt.sh requests use
a 30 s timeout rather than D3's 15 s, since large domains routinely take longer.)*
Issuer comparison parses both sides with `javax.naming.ldap.LdapName` and compares the RDN sets, so
crt.sh's `C=US, O=Let's Encrypt, CN=R11` equals Java's `CN=R11,O=Let's Encrypt,C=US`.
*(Corrected 2026-09-25 at design audit: exact RDN-set equality was wrong as written. Java's
`X500Principal.getName()` hex-encodes attributes it has no keyword for, e.g. `emailAddress` becomes
`1.2.840.113549.1.9.1=#16…`, while crt.sh spells it out, so the two sets can never be equal for such
an issuer. `IssuerNames.same` compares the keyword-named attributes present on both sides, requires
`CN` to be among them, and requires every shared attribute to be equal. Serial equality is still
required as well.)* Only
issuances **currently valid at run time** are checked; expired ones stay in the export as history
and raise nothing. ~~The cross-check is against **every observation in the run** whose host falls
under that CT domain, not the one row.~~ *(Superseded 2026-09-25 by the implementation note above:
the cross-check is against every leaf served anywhere in the run. This sentence contradicted that
note and is struck so the record has one rule.)* With `--ct-fetch-der` (default off), final-certificate
entries that matched on `(issuer, serial)` are fetched as DER from `https://crt.sh/?d=<id>` and
must also match on SHA-256; a mismatch raises `CT_FINGERPRINT_MISMATCH` (High). This closes
backlog D7 as an opt-in.

**CAA (CAA-01/02, amends D4).** The climb covers every label down to the TLD. Queries go out through
`SimpleResolver.send` with the AD flag set, not `Lookup` (F11). The answer's CAA RRs are taken
whatever owner the CNAME chain ends at. NXDOMAIN and NODATA continue the climb; any other rcode or
an exception makes the check `ERROR`, with the rcode or message as received. `CaaResolution` records
the resolver. `CAA_NO_ACCOUNT_BINDING`/`CAA_NO_METHOD_BINDING` skip values with an empty issuer
domain. `CAA_WILDCARD_UNRESTRICTED` needs at least one `issue` naming a CA and no `issuewild`.
CAA runs once per distinct host.

**Findings and reports (RPT-01, amends D1).** `Finding` gains `domain, host, evidence, observedAt`.
Why-it-matters and remediation text come from one `FindingCatalog` keyed by type, so every finding
has both. Outputs per run:
- `audit-<ts>.json`: everything, and the `--baseline` input.
- `audit-<ts>-findings.csv`: `ct_domain, host, type, severity, subject, detail, why, remediation,
  evidence, observed_at`.
- `audit-<ts>-coverage.csv`: one row per (subject, check) with `OK | ERROR | NOT_CHECKED` and the
  message. This is where a gap is kept from looking like a pass.
  *(Made explicit 2026-09-25 at design audit: `OK` means the check ran on everything under that
  subject. If a host:port resolves to N addresses and some of them are unreachable, each
  unreachable address gets its own `ver` row, subject `host:port@address`, status `ERROR`, with the
  error as received. Those rows count toward the run's failed-check total and exit code. A partial
  result is never an `OK` row that only a free-text message qualifies.)*
- `audit-<ts>-report.md`: the template (`src/main/resources/audit-report-template.md`) with the
  counts, findings tables, coverage and inventory filled in, and `TODO (hand-written)` markers for
  the executive summary narrative and automation-readiness section (AUTO is not in Phase 0). Hosts
  with a blank `owner` are listed under ownership gaps, as a list, not as a finding (OWN-04 is not
  in Phase 0).

**Logging (F12).** Add `log4j-slf4j2-impl` (runtimeOnly), same version as the existing log4j.

### Non-goals (this record)

- **No second CT provider.** The user's call (F9). The interface stays, so adding one later changes
  one class.
- **No public suffix list.** Operators give `domain` when they have it; without it, CT is scoped to
  the host and the export says so.
- **No `CertPathBuilder`/PKIX validation.** `TrustAnchors` only answers "is the last served
  certificate signed by a JDK anchor?"; CHN-04's client profiles stay deferred.
- **No PDF/HTML.** The Markdown report is the "template filled partly by hand".

### Acceptance gate (field checks only)

Unit tests cannot close these. They are open until someone runs them:
1. A live `-audit` against at least three real domains produces all four outputs. **Open:** one
   domain run so far (example.com, two hosts, 2026-09-25); all four outputs written.
2. A crt.sh outage during a run shows its status and body in the coverage CSV and report. **Met
   2026-09-25:** crt.sh answered 502 on both live runs, and the coverage CSV and report carry
   `crt.sh HTTP 502 … (attempt 2 of 2): <html>…502 Bad Gateway…` verbatim, with CT-03 `NOT_CHECKED`.
3. A CT pull for a domain matches a manual crt.sh query by hand. **Open:** crt.sh was down for
   every attempt on 2026-09-25, so the CT parsing and the `%.domain` subdomain query have never run
   against a real crt.sh answer.
4. A host behind round-robin DNS produces one observation per A/AAAA record. **Met 2026-09-25:**
   example.com resolved to two IPv4 addresses and one IPv6 address, giving three observations with
   TLS 1.3 and a 4-certificate chain each.

---

## D4 — CAA-01/CAA-02: effective CAA resolution and completeness findings

**Status:** designed, not implemented. **Depends on:** D1 (`Finding`, `AuditRunner`).

### Findings

- **F1.** No DNS resolution of any kind beyond implicit `Socket.connect`/`InetAddress` host lookups
  exists anywhere in the repo (confirmed across all 10 `src/main/java` files) — CAA-01 needs a raw
  record-type-257 query, which nothing here provides.
- **F2.** `com.sun.jndi.dns.DnsContextFactory` (JDK-builtin, no new dependency) was considered and
  rejected: Sun's JNDI DNS provider's attribute-ID table predates CAA (RFC 6844, 2011) by roughly a
  decade and has never been extended for it — it exposes A/AAAA/MX/NS/CNAME/TXT/SOA/PTR/SRV/NAPTR
  as named JNDI attributes but has no CAA mnemonic, and there is no supported way to request an
  arbitrary raw RR type through it. This is a dead end, not a missing-flag problem.
- **F3.** `dnsjava` (`dnsjava:dnsjava`) has a native `org.xbill.DNS.CAARecord` class, is
  BSD-3-Clause (permissive, compatible with this repo's Apache 2.0), and has no mandatory
  transitive runtime dependency. It is the standard, well-maintained pure-Java DNS library and is
  the only realistic option that doesn't mean hand-rolling wire-format DNS parsing, EDNS0, and
  TCP-fallback — out of proportion to a script-grade Phase 0 check. **Decision: add it.** Pin the
  exact version and re-confirm the license text on the actual downloaded POM at implementation
  time (verified via web search only, not the artifact itself, during design).
- **F4.** dnsjava's `Lookup` class follows CNAME chains automatically for whatever type it's asked
  to resolve, including CAA — RFC 8659 §3's CNAME-following requirement is satisfied by the
  library itself, not something to hand-roll.
- **F5.** RFC 8659 tree-climbing (walk from the queried name up to the registrable domain, taking
  the first non-empty CAA set) is **not** provided by any library and must be hand-rolled — it's a
  simple loop, not a library gap.
- **F6.** Determining the true registrable-domain boundary for the climb requires a public suffix
  list (multi-part TLDs like `co.uk`, `github.io`). No PSL dependency exists in this repo and none
  is proposed here (see Non-goals).

### Design

New package `com.codecatalyst.audit.caa`:

- **`CaaResolver.java`** — `CaaResolution resolve(String domain)`. Algorithm:
  1. Build the label list of `domain` (e.g. `www.example.com` → `[www, example, com]`).
  2. Walk from the full name toward the apex, one label shorter each step, **stopping once the
     candidate has exactly 2 labels** (e.g. `example.com`) — the naive-PSL heuristic (Non-goals).
  3. At each candidate, run a dnsjava `Lookup(candidate, Type.CAA)` against a `SimpleResolver`
     pointed at a public recursive resolver (default `8.8.8.8`, overridable via `--resolver` on the
     `-audit` verb — reuses the CLI's existing flag-parsing convention). `Lookup` handles CNAME
     redirection internally.
  4. First candidate with a non-empty CAA RRset wins; record `foundAtName = candidate`.
  5. If the climb reaches the 2-label floor with nothing found, `records` is empty and
     `foundAtName` is the original queried domain (CAA-01's "no CAA of its own → parent's record,
     with the owner name it was found at" is satisfied by step 4; the empty case feeds
     `CAA_ABSENT` in `CaaEvaluator`).
  6. `dnssecStatus`: read the AD (Authenticated Data) bit off the DNS response header dnsjava
     exposes on the `Lookup`/`Message` object. `"VALIDATED_BY_RESOLVER"` if set, else
     `"UNVALIDATED"`. This is **not** independent RRSIG-chain validation — see Non-goals.
  7. Each `CAARecord`'s `getTag()`/`getValue()`/`getFlags()` is copied into a `CaaProperty(tag,
     value, critical)` record. The `value` string for `issue`/`issuewild` follows
     `issuer-domain-name *(";" parameter)` grammar (RFC 8659 §4.1-4.2) and is parsed by a small
     helper (`CaaProperty.parseIssueValue()`) splitting on `;`, trimming, first token = CA domain,
     remainder = `key=value` pairs — no library needed, this is pure string handling.

- **`CaaEvaluator.java`** — pure function `List<Finding> evaluate(String domain, CaaResolution r)`:
  - `CAA_ABSENT` — `r.records()` empty.
  - `CAA_NO_ACCOUNT_BINDING` — any `issue`/`issuewild` value missing an `accounturi` parameter.
  - `CAA_NO_METHOD_BINDING` — any `issue`/`issuewild` value missing a `validationmethods` parameter.
  - `CAA_WILDCARD_UNRESTRICTED` — `issue` present, no `issuewild` tag anywhere in the found RRset
    (RFC 8659 §5.2: wildcard issuance inherits from `issue` when `issuewild` is absent).
  - Each finding's `detail` includes the one-sentence permission explanation and a reference to
    the March 2027 CA mandate, matching CAA-02's acceptance text verbatim where practical (e.g.
    reproducing F1's pre-fix record — `issue "letsencrypt.org"`, no parameters — must raise both
    `CAA_NO_ACCOUNT_BINDING` and `CAA_NO_METHOD_BINDING`; this is a direct unit-test case, no lab
    fixture needed since it's pure string/logic evaluation).
  - `iodef` tag is recorded on the export (D1's `AuditReportWriter`) but produces no finding in
    Phase 0 — CAA-02 doesn't ask for one.

Severity mapping (reusing Monitor360's own ALR-02 table verbatim, since it's the same finding
vocabulary): `CAA_NO_ACCOUNT_BINDING` → Medium; `CAA_ABSENT`, `CAA_NO_METHOD_BINDING`,
`CAA_WILDCARD_UNRESTRICTED` → Low.

`AuditRunner` (D1) calls `CaaResolver.resolve` once per domain and feeds the result to both
`CaaEvaluator` (findings) and the report writer (raw CAA record dump).

### Non-goals (this record)

- **No public suffix list.** The 2-label climb-floor heuristic misclimbs for multi-part TLDs
  (`co.uk`, `github.io`, `com.au`) — a domain like `www.example.co.uk` climbs to `co.uk` and stops
  one level too high, querying a non-registrable name. Filed to `docs/backlog.md` for Phase 1
  (either a bundled small PSL data file, checked in and periodically refreshed, or accept Guava's
  `InternetDomainName` if Guava is ever pulled in for another reason — not justified standalone
  for this).
- **No independent DNSSEC validation.** Only the upstream public resolver's AD bit is relayed.
  True chain-of-trust validation (RRSIG verification to the root) needs either a validating
  resolver library or running against a local validating resolver — out of Phase 0's hour budget.
  Filed to backlog.
- **CAA-03/04/05 are not built, not even optionally.** The Phase 0 bullet in the requirements
  doc's §8 lists only CAA-01 and CAA-02. CAA-03 (declared intent) needs persisted per-org policy
  and a place to declare it — no such concept exists in a stateless CLI. CAA-04 (drift) needs
  history across runs; unlike CHN-02 (D2), no baseline-diff shortcut is added here since it's not
  in Phase 0's asked scope — don't build it just because the mechanism would be similar. CAA-05
  needs both CAA-04's snapshots and CT-03. All filed to `docs/backlog.md`.
- **No DNSSEC-aware resolver failover or DoH.** Plain UDP/TCP DNS to one configured resolver; if
  it's unreachable the domain's CAA check fails soft (`checkError` field on that domain's result,
  per D1's per-check isolation) rather than aborting the run.

---

## D3 — CT-01..03: Certificate Transparency pull and reconciliation

**Status:** designed, not implemented. **Depends on:** D1 (`Finding`, `AuditRunner`), reads
observed certs from D2's `ServedStateProber` output for CT-03's cross-check.

### Findings

- **F1.** No HTTP client, no CT log client, no CT-related code of any kind exists in this repo.
- **F2.** The requirements doc's §11 open question 1 explicitly defers the crt.sh-vs-commercial-API
  decision to "after Phase 0 shows real volume" — meaning the doc's own author already expects
  crt.sh at Phase 0.
- **F3 (verified live, 2026-09-25).** crt.sh's actual throttle today is **5 requests per minute
  per source IP** (tightened from an earlier 60/min after DDoS mitigation work) — tighter than the
  commonly-cited figure. It has no published formal API contract, no authentication, and
  `?output=json` on any query URL returns JSON. This is materially stricter than "be polite" — it's
  a hard design constraint: roughly one request every 12 seconds, sustained, or crt.sh starts
  dropping/blocking the source IP.
- **F4.** crt.sh's JSON schema is informal and its `entry_type`/precert-vs-final distinction is not
  a clean documented boolean in the output — RFC 6962 is explicit that a precertificate and its
  final certificate share `(issuer, serial)`, so reconciling on that pair (which the requirements
  doc's own CT-02 text already specifies) sidesteps crt.sh's schema quirks entirely rather than
  depending on them.
- **F5.** crt.sh's JSON rows carry `issuer_name` (free-text DN rendering) and `serial_number` (hex
    string) but not a SHA-256 fingerprint or full DER — getting either means one extra request per
  issuance (`https://crt.sh/?d=<id>`, raw DER), which at 5 req/min would make CT-03 the dominant
  cost of every audit for any domain with more than a handful of historical issuances.

### Design

**Decision: unauthenticated HTTPS GET to crt.sh's JSON endpoint, behind an interface, rate-limited
client-side to stay under its real throttle.** Reasoning: Phase 0 audits are tens of domains per
engagement, not thousands (NFR-02's 5,000-domain/20,000-address scale is explicitly Phase 1/2
platform territory, not this CLI) — a slow, polite crt.sh client is entirely adequate for a
manually-triggered, human-supervised audit run, and a paid CT API is real recurring cost with no
revenue yet to justify it (Phase 0's own gate is "at least one paid audit," i.e. revenue doesn't
exist until Phase 0 ships). If crt.sh proves too unreliable during actual audits, only
`CrtShSource` needs replacing — the interface is exactly what makes that swap cheap later, per the
requirements doc's own ask.

New package `com.codecatalyst.audit.ct`:

- **`CtLogSource.java`** — interface: `List<CtIssuance> fetch(String domain) throws
  CtLookupException`. `CtIssuance` is a record: `issuerName, serialNumberHex, commonName,
  sanNames(List<String>), notBefore, notAfter, entryTimestamp, logRef`.
- **`CrtShSource.java implements CtLogSource`** — uses `java.net.http.HttpClient` (JDK stdlib,
  Java 17+, no new dependency) with an explicit per-request timeout (15s) against
  `https://crt.sh/?q=<domain>&output=json`. A `Semaphore`-backed minimum-interval gate (one
  `acquire`/scheduled `release` every 12–13s, shared across the whole `-audit` run, not per
  domain) enforces the 5/min ceiling regardless of how many domains the CSV lists — this makes a
  20-domain CT pass take roughly 4 minutes, which is fine for a tool invoked once per audit
  engagement, not on a tight interactive loop. One retry on `IOException`/`HTTP 5xx`/timeout, then
  the domain's CT result is marked `checkError` and the run continues (fail-soft, matches D1's
  per-check isolation).
- **`CtReconciler.java`** — pure functions:
  - `List<CtIssuance> reconcile(List<CtIssuance> raw)` — dedupes by `(issuerName, serialNumberHex)`
    (CT-02), keeping the earliest `entryTimestamp` as `firstSeen`.
  - `List<Finding> detectUnobserved(List<CtIssuance> reconciled, List<ObservedCert> observed)`
    (CT-03) — matches purely on **serial number** (parsed to `BigInteger` from both crt.sh's hex
    string and `X509Certificate.getSerialNumber()`), not full fingerprint, and not DN string
    equality. Serial-number collision across different issuers is astronomically unlikely at this
    scale, and DN-string comparison is fragile (RDN ordering/encoding differs between crt.sh's
    rendering and Java's `X500Principal.getName()` canonicalization) — a false negative there
    (a real unobserved issuance silently missed) is worse than the imprecision of skipping the DN
    cross-check, so serial number is the sole match key; `issuerName` is carried on the finding as
    informational context only. An issuance whose serial matches no `ObservedCert` from D2's
    `ServedStateProber` pass over the same domain raises `UNOBSERVED_ISSUANCE`.
  - Severity: Medium by default. The doc's ALR-02 table also escalates to Critical when the CA is
    outside declared intent — **that escalation path is structurally unreachable in Phase 0**
    (CAA-03's declared-intent mechanism doesn't exist yet, see D4 Non-goals), not a bug; stated
    explicitly so it isn't "fixed" by inventing a declared-intent shortcut later without reading
    D4 first.

`AuditRunner` (D1) calls `CrtShSource.fetch` → `CtReconciler.reconcile` → (after D2's VER-01 pass
completes for the same domain) `CtReconciler.detectUnobserved`.

### Non-goals (this record)

- **No incremental/polling CT ingestion.** CT-01's acceptance criterion ("newly issued certificate
  appears within one polling interval, default 6h") describes Phase 1's continuous-monitoring
  behavior. Phase 0 is a one-shot pull per invocation — there is no daemon, no stored
  last-seen-entry cursor, no scheduling. Re-running `-audit` re-pulls everything for every listed
  domain, every time.
- **No full-DER download for exact SHA-256 fingerprint matching in CT-03.** Matching is by serial
  number only (F5, above). Filed to `docs/backlog.md` as a Phase 1 sharpening if real audits show
  serial-only matching produces false positives (a coincidental serial collision has never been
  observed in practice by any CT tooling the author is aware of, but it's worth stating as an
  assumption rather than a proof).
- **CT-04 (new-issuance alerting) and CT-05 (automation-interval inference) are not built.** Both
  are outside the Phase 0 bullet list in §8. CT-04 needs a persisted "already notified" cursor and
  a delivery channel; CT-05 needs issuance history trending over months, not a single run. Filed
  to `docs/backlog.md`.
- **No CT provider fallback/multi-source merge.** One source, `CrtShSource`, used directly. The
  interface exists so a second implementation can be added later, not so two run concurrently now.

---

## D2 — VER-01/VER-02, CHN-01..03: per-address served-state and chain capture

**Status:** designed, not implemented. **Depends on:** D1 (`Finding`, `AuditRunner`).

### Findings

- **F1 (confirmed).** `FetchCertificates.fetchCertMetadata()`
  (`src/main/java/com/codecatalyst/net/FetchCertificates.java:64-79`) does one TLS handshake and
  returns only `(X509Certificate) serverCerts[0]` — the full chain from
  `sslSocket.getSession().getPeerCertificates()` is fetched by the JSSE layer and then discarded at
  that cast. This is exactly CHN-01's gap.
- **F2 (confirmed).** `PersistenceManager.saveCertificate(String, X509Certificate[])`
  (`persist/PersistenceManager.java:70-86`) is a full-chain-aware keystore overload that exists and
  is called from nowhere; `CertConstants.LEAF`/`CHAIN_CERT` alias suffixes back it. **This confirms
  the general direction (capture the full chain, not just the leaf) is right, but the overload
  itself is the wrong persistence target for audit-kit output**: it stores certs by
  `alias`/`alias-inter-N` in the long-lived local inventory keystore, with no notion of a resolved
  IP address, no per-observation timestamp, and no dedup-by-content beyond what one alias happens
  to hold. The audit kit's findings (VER-02 node divergence, CHN-02 chain-hash comparison) need
  per-address, per-run structured records, not another keystore alias scheme. Reusing this overload
  would conflate "the tool's persistent local inventory of certs it has seen" with "one audit run's
  transient evidence" — two different lifetimes and shapes. **Decision: do not route audit output
  through `PersistenceManager` at all** (see Non-goals) — but the fact this overload was half-built
  validates that `FetchCertificates` should grow a chain-returning method, which both this feature
  and a future non-audit `-scan --full-chain` enhancement to the existing inventory path could
  share.
- **F3 (confirmed).** `NetworkScanner` (`net/NetworkScanner.java`) is dead code — nothing in
  `CertManager`'s dispatch calls it. It is also **unsuitable for direct reuse here as-is**: its
  `scanAndStore` fires `executor.submit()` lambdas that catch-and-print exceptions with no
  `Future` collection and calls `executor.shutdown()` without ever awaiting completion — a
  fire-and-forget shape that can't return per-address results to a caller, which VER-01/VER-02
  fundamentally need (the whole point is comparing results across addresses). A new, small
  `CompletableFuture`-based prober is designed below instead of extending this class.
- **F4 (confirmed).** SNI is already sent correctly — `factory.createSocket(socket, host, port,
  true)` (`FetchCertificates.java:71`) uses the JSSE default SNI behavior for that overload. No
  change needed; carried forward into the new address-aware constructor below.
- **F5 (confirmed).** No DNS multi-address resolution exists — `extractHosts` in `CertManager.java`
  only tokenizes CLI arguments; nothing calls `InetAddress.getAllByName`. This is VER-01's actual
  gap.

### Design

**`FetchCertificates.java` — edited, not replaced.** Add:
- A new constructor `FetchCertificates(InetAddress address, String sniHost, int port)` — connects
  the raw socket to the literal resolved `address` (`new InetSocketAddress(address, port)`, not
  hostname-based resolution) while still passing `sniHost` to `factory.createSocket(socket,
  sniHost, port, true)` for correct SNI. This is the one behavioral gap the existing
  host-string-only constructors can't cover: probing a specific address while still identifying the
  target hostname over TLS.
- A new method `X509Certificate[] fetchChain() throws CertificateException` — same handshake as
  today, but returns the full `getPeerCertificates()` array cast to `X509Certificate[]`, in the
  order JSSE returns it (leaf-first, per the JDK's documented behavior). `fetchCertMetadata()` is
  left as-is (existing `-scan`/`-list` callers are untouched) but is refactored to call
  `fetchChain()[0]` internally to avoid duplicating the handshake code.
- Also captures `sslSocket.getSession().getProtocol()` and `getCipherSuite()` — needed for VER-01's
  "negotiated protocol and cipher" field, currently discarded entirely.

New package `com.codecatalyst.audit`:

- **`AddressObservation.java`** — record: `address (InetAddress), reachable (boolean), chain
  (X509Certificate[]), leafSha256 (String), chainHash (String), protocol, cipher, error
  (String, nullable)`.
- **`ServedStateProber.java`** — `List<AddressObservation> probe(String hostname, int port)`:
  1. `InetAddress.getAllByName(hostname)` — resolves all A and AAAA records (VER-01). IPv6
     addresses are scanned exactly like IPv4; no special-casing.
  2. For each address, submit a `FetchCertificates(address, hostname, port).fetchChain()` call to a
     small bounded `ExecutorService` (fixed pool, default 4 — politeness default, overridable via
     `--concurrency` on `-audit`) and collect via `CompletableFuture.allOf`. A single address
     failing (timeout, connection refused, TLS failure) produces `AddressObservation(address,
     reachable=false, ..., error=<message>)` — it does **not** fail the whole target (VER-01's
     explicit acceptance criterion).
  3. `leafSha256` / `chainHash`: SHA-256 (`MessageDigest.getInstance("SHA-256")`) over
     `chain[0].getEncoded()` for the leaf; chain hash is SHA-256 over the concatenation of the
     ordered per-cert fingerprints (CHN-02's stated formula).
- **`ChainAnalyzer.java`** — pure functions, no network I/O:
  - `String chainHash(X509Certificate[] chain)` (shared with the prober above).
  - `Finding detectNodeDivergence(String domain, int port, List<AddressObservation> obs)` (VER-02)
    — if reachable observations' `leafSha256` or `chainHash` values aren't all equal, raise
    `NODE_DIVERGENCE` naming every diverging address and its fingerprint pair, not just one.
  - `List<Finding> detectChainDefects(AddressObservation obs)` (CHN-03, script-grade subset —
    chosen for being expressible with plain `X509Certificate` inspection, no `CertPathBuilder`/
    trust-store wiring):
    - `ROOT_INCLUDED` — last cert in the served chain is self-signed
      (`getSubjectX500Principal().equals(getIssuerX500Principal())`).
    - `EXPIRED_IN_CHAIN` — any cert's `checkValidity()` throws, naming which position expired.
    - `WRONG_ORDER` — consecutive certs' issuer/subject DNs don't chain
      (`chain[i].getIssuerX500Principal()` should equal `chain[i+1].getSubjectX500Principal()`) but
      a *later* cert in the served set does match — the certs are present but out of sequence.
    - `MISSING_INTERMEDIATE` vs `AIA_ONLY_COMPLETION` — the last served cert's issuer isn't any
      subject present in the chain (doesn't terminate within what was served); check that cert's
      Authority Information Access extension (OID `1.3.6.1.5.5.7.1.1`) for a caIssuers URL — if
      present, `AIA_ONLY_COMPLETION`, else `MISSING_INTERMEDIATE`.
    - `WEAK_SIGNATURE` — `getSigAlgName()` contains `MD5` or `SHA1` (case-insensitive), any
      position.
    - `WEAK_KEY` — `getPublicKey()` is `RSAPublicKey` with modulus `< 2048` bits, or `ECPublicKey`
      with field size `< 224` bits, any position.
  - Severity (ALR-02 reuse, as in D3/D4): `EXPIRED_IN_CHAIN` → Critical (matches "served
    certificate expired"); `NODE_DIVERGENCE` → High; every other CHN-03 defect type → Medium.
  - `Finding detectChainChanged(String domain, AddressObservation current, AddressObservation
    baseline)` (CHN-02) — **only produced when a `--baseline <path>` was supplied** to `-audit`
    (see D1). Raises `CHAIN_CHANGED` when `chainHash` differs but `leafSha256` matches, between the
    current run's observation and the same `(domain, address)` pair loaded from a prior run's JSON
    export. Reasoning: CHN-02's acceptance criterion ("swapping the intermediate bundle... without
    changing the leaf") is inherently a two-visit comparison, and Phase 0 has no database to hold
    history — reusing the JSON export D1 already produces as an optional input, rather than adding
    any new persistence, is the cheapest correct way to get this. If no baseline is given,
    `CHAIN_CHANGED` is simply never raised for that run — stated explicitly rather than silently
    doing nothing.

### Non-goals (this record)

- **Audit observations are never written to `PersistenceManager`'s keystore.** The existing
  `-scan`/`-list`/`-rm`/`-update` inventory feature and the audit kit are deliberately kept
  separate: the keystore is a long-lived "certs this operator has looked at" store keyed by alias;
  the audit kit is a self-contained, per-run evidence set that lives only in memory and in the
  JSON/CSV export (D1). No new keystore alias scheme is invented for per-address data.
- **`NetworkScanner` is left untouched and still dead.** Not wired in, not deleted, not extended —
  it remains a pre-existing, separately-tracked piece of dead code (see backlog) orthogonal to this
  work; `ServedStateProber` is new and purpose-built instead (F3, above).
- **No `CertPathBuilder`/PKIX validation anywhere in CHN-03.** All defect detection is
  per-certificate field inspection on the served chain as a flat array, not a real path build
  against any trust store. This deliberately does not attempt CHN-04's client-profile validation
  (browser/Java/legacy trust stores) — that's explicitly P1 in the requirements doc and a
  materially larger lift (bundled CCADB/cacerts snapshots, `PKIXParameters`, AIA-fetch toggling per
  profile). Filed to `docs/backlog.md`, not attempted here even partially.
- **No CHN-05 (revocation/CRL/OCSP across the chain).** No revocation checking of any kind exists
  in Phase 0. Filed to backlog; the baseline platform (Monitor360) already has leaf-only CRL
  lookup for reference when this is eventually built.
- **No exhaustive CHN-03 defect catalogue.** The six defect types above are what's cheaply
  expressible without a real path-building engine; anything requiring simulated client trust-store
  behavior is CHN-04's job, not this record's.

---

## D1 — Audit kit shape: CSV input, `-audit` CLI verb, shared data model, report export

**Status:** designed, not implemented. This record defines the contracts D2–D4 plug into; it does
not itself implement CT, CAA, or served-state logic.

### Findings

- **F1 (confirmed).** No CSV parsing exists anywhere in the repo. Today every scan target comes
  directly from CLI args via `extractHosts`/`extractPorts` in `CertManager.java`.
- **F2 (confirmed).** `CommandParamsEnum` (`common/CommandParamsEnum.java`) plus a hand-rolled
  `switch` in `CertManager.parseAndExecute` is the entire CLI dispatch mechanism — no argument-
  parsing library, matching CLAUDE.md's documented convention. The audit verb follows the same
  shape rather than introducing one.
- **F3.** The requirements doc's OWN-05/INT-04 text describes CSV columns for owners and tags —
  but those belong to OWN-01/OWN-05, both explicitly Phase 1/2 (no ownership or tagging concept
  exists anywhere in this repo, and Phase 0's §8 bullet list doesn't mention OWN at all). A Phase 0
  CSV that tries to carry owner/tag columns would be building infrastructure with nothing yet to
  consume it. **Decision: the Phase 0 CSV carries only `domain` (required) and `port` (optional,
  default 443)** — the minimum INT-04 needs to drive an audit run, nothing more.
- **F4.** RPT-01 is marked ✋ (manual-first): "the first three audits can be delivered by script
  plus a hand-written report before the feature is productised." Read literally against the
  acceptance text (executive summary, findings, inventory appendix, evidence links) that is a
  **data export a human formats into a report**, not a PDF/HTML generator — building either would
  be exactly the kind of pre-sales productisation the ✋ marker says to defer.

### Design

**CLI verb.** Add `AUDIT("-audit")` to `CommandParamsEnum` (`common/CommandParamsEnum.java`),
following the existing enum-plus-switch pattern exactly (`getEnum` gets a new `case "-audit" ->
AUDIT`). New dispatch arm in `CertManager.parseAndExecute`:

```
-audit --csv <path> [--out <dir>] [--baseline <path>] [--resolver <ip>] [--concurrency <n>]
```

`--csv` is required; every other flag is optional with the defaults stated in D2/D3/D4 and below.
Parsing reuses the existing hand-rolled array-scanning style (no new CLI library), consistent with
CLAUDE.md's stated convention. Dispatches to `new AuditRunner(...).run(csvPath)`.

New package `com.codecatalyst.audit`:

- **`AuditTarget.java`** — record: `domain (String), port (int, default 443)`.
- **`CsvTargetReader.java`** (INT-04) — `CsvReadResult read(Path csvPath)` returning both the
  successfully parsed `List<AuditTarget>` and a `List<RowError>` (`lineNumber, rawLine, reason`).
  Format: one header row (`domain` or `domain,port`, sniffed by checking whether the first cell of
  row 1 parses as neither a valid hostname nor is literally `domain`) then one target per line.
  Per-row validation: `domain` non-blank, `port` (if present) numeric 1–65535 via the *existing*
  `CertManager.parsePorts` logic (reused, not duplicated — `parsePorts` is already `public static`
  in `CertManager.java:373`). A malformed row is recorded in `RowError` and **skipped**, not fatal
  — matches INT-04's acceptance criterion ("row-level validation errors reported, not a whole-file
  rejection") directly. No CSV library added: fields are two plain scalars with no embedded commas
  or quoting expected, so a `line.split(",")` per row (mirroring `extractHosts`'s existing comma-
  split idiom) is sufficient and avoids a dependency for a two-column format.
- **`Finding.java`** — record: `type (String), severity (Severity enum: CRITICAL/HIGH/MEDIUM/LOW),
  subject (String — the domain, address, or "domain:address" the finding is about), detail
  (String — one-sentence human explanation, per CAA-02's own stated style)`.
- **`DomainAuditResult.java`** — record aggregating one CSV row's full output: `target
  (AuditTarget), addressObservations (List<AddressObservation>, from D2), chainCertificates
  (Map<String sha256, CertSummary> — in-run dedup store, CHN-01's "shared across observations"
  requirement satisfied in-memory for the duration of one run, not persisted), ctIssuances
  (List<CtIssuance>, from D3), caa (CaaResolution, from D4), findings (List<Finding>), checkErrors
  (Map<String checkName, String message> — per-check failure isolation, e.g. `"ct" ->
  "crt.sh timeout"` doesn't block `"caa"` or `"ver"` for the same domain)`.
- **`AuditRunner.java`** — orchestrates, per `AuditTarget`, independently and in parallel across
  domains (bounded pool, same `--concurrency` default as D2's prober): call D2's
  `ServedStateProber.probe`, D3's `CrtShSource.fetch` → `CtReconciler`, D4's `CaaResolver.resolve`
  → `CaaEvaluator`; assemble chain-defect and node-divergence findings via D2's `ChainAnalyzer`;
  assemble CT-03's cross-check once both VER-01 and CT-01 results for that domain exist. Any one
  check throwing is caught locally and recorded in `checkErrors` — never aborts the domain's other
  checks or another domain's run.
- **`AuditReportWriter.java`** (RPT-01, Phase 0 half) — writes two files per run, both driven by
  `List<DomainAuditResult>`:
  - `audit-<timestamp>.json` — full structured export (targets, observations, chain cert dedup
    table, CT issuances, CAA records, findings, check errors) via the existing Jackson dependency
    (`writerWithDefaultPrettyPrinter()`, matching `NinjaScanner`'s existing use of the same
    library). This file is also what `--baseline` (D2's `CHAIN_CHANGED`) reads back in on a later
    run.
  - `audit-<timestamp>-findings.csv` — one row per `Finding` (`domain, type, severity, subject,
    detail`), a flat table meant to be pasted straight into a spreadsheet or the hand-written
    report template, since the doc's own baseline (F2, source doc §2 F2) says clients already
    think in Excel terms. Written with the same manual-split/no-library approach as
    `CsvTargetReader` (values here are also comma-free in practice; `detail` is defensively
    comma-escaped by wrapping in quotes since it's free text).
  - Output directory: `--out <dir>` if given, else the current working directory.

### Non-goals (this record, and for Phase 0 overall)

- **No PDF or HTML report generation.** RPT-01's Phase 0 deliverable, per its own ✋ marker, is the
  JSON+CSV export above; a human turns that into the actual audit report. This is explicitly not a
  smaller/uglier version of Monitor360's eventual PDF pipeline (D137/D144 over in Monitor360) — it
  is a different, deliberately manual, deliverable.
- **No findings persistence or database beyond one run's export files.** This is a CLI, not a
  service. `--baseline` (D2) is the only cross-run mechanism, and it's optional, file-based, and
  manual — the user decides when to pass a prior run's JSON back in.
- **No scheduling or polling.** `-audit` runs once per invocation and exits. There is no daemon, no
  cron integration, no "every 6 hours" behavior anywhere in Phase 0 — that's Phase 1 platform
  scope, already correctly deferred in `docs/backlog.md`'s existing "Deferred scope" entry.
- **No multi-tenant anything, no accounts, no org concept.** One local user, one report per run,
  same trust model as the existing keystore (local file, whoever runs the CLI).
- **No owner/tag columns in the CSV (OWN-01/OWN-05).** Deliberately excluded from Phase 0's INT-04
  scope (F3, above) since nothing downstream consumes them yet.
- **No per-check opt-out flags** (e.g. `--no-ct`, `--no-caa`). An audit runs all four checks by
  default; adding a flag matrix for a tool used a handful of times per engagement is speculative
  configurability with no current user. If a real need shows up (e.g. crt.sh is down mid-audit and
  the operator wants to re-run just CAA/VER), add it then.
- **Zero new secrets introduced.** crt.sh (D3) needs no API key; dnsjava's public resolvers (D4)
  need no API key. Phase 0 does not touch or extend the existing hardcoded keystore password
  (CLAUDE.md gotcha 5) — out of scope, and deliberately not copying that pattern into any new code
  path here, since there's nothing secret-bearing to store.
- **`RabbitMQ` (`com.rabbitmq:amqp-client`, already a `build.gradle` dependency) is not used
  anywhere in this design.** It's irrelevant to a synchronous, single-process CLI audit run; no
  reasoning is given for *not* using it beyond noting it was considered and is orthogonal.
