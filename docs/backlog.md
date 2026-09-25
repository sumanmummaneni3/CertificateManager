<!--
Append-only gap log. Anything found and not fixed goes here the same session it's found — a gap
that's only in a conversation gets rediscovered in three months. Superseded rows are struck through
and re-dated in place, never deleted. Row format and severity meanings: see the design-loop skill's
references/backlog-row.md.
-->

## Deferred scope

- **Everything in the Certificate Verification Layer requirements doc beyond Phase 0** (VER, CHN,
  CT, CAA, OWN, AUTO, RPT, ALR, INT as full platform epics; agent protocol changes AGT-01..05) is
  Monitor360 platform work, gated behind Phase 0's own sales-validation gate ("three audits
  offered; at least one paid"). See `Monitor360/Monitor360-Certificate-Verification-Requirements.md`
  §8 for the full phasing and `Monitor360/docs/backlog.md` D153 for the Monitor360-side deferral
  row. Filed 2026-09-25.

## Bucket 1 — Design-level TODOs

Need an architectural decision or a blueprint before anyone starts coding. Found while designing
D1–D4 (Phase 0 audit kit); none block Phase 0 itself, all are compromises made explicit in the
D2/D3/D4 Non-goals so they aren't silently "fixed" later without reading the record first.

| # | Severity | Item | Where |
|---|---|---|---|
| D5 | ~~MED~~ LOW | ~~**CAA-01's tree-climb has no public suffix list.** Filed 2026-09-25 at D4's design, §Non-goals. The climb stops at a naive last-2-labels heuristic (`example.co.uk` → stops at `co.uk`, one level too high) instead of the true registrable-domain boundary. Fix shape: bundle a small, periodically-refreshed PSL data file, or pull in Guava's `InternetDomainName` if Guava is ever justified for another reason. Not done now because no PSL dependency exists in this repo and adding one standalone for a heuristic that's usually right for common TLDs isn't worth it before Phase 0 shows which client domains actually hit the multi-part-TLD case.~~ (Originally filed against `docs/architecture.md` D4.) **Re-scoped 2026-09-25 by D8:** CAA never needed a public suffix list, because RFC 8659 climbs to the TLD and D8 does exactly that. The remaining need is CT scoping: without a `domain` column, CT is queried for the host itself (`HOST_ONLY`, stated in the export). A bundled PSL would let the kit infer the registrable domain. It is low priority because operators can fill the `domain` column. | `docs/architecture.md` D8; `audit/AuditTarget.java` |
| D6 | LOW | **CAA-01's DNSSEC status is the upstream resolver's AD bit, not independent validation.** Filed 2026-09-25 at D4's design, §Non-goals. A compromised or misconfigured public resolver could report `VALIDATED_BY_RESOLVER` incorrectly. Fix shape: a validating-resolver library or a local validating resolver. Not done now — independent RRSIG-chain validation is a materially larger lift than the rest of D4 combined, and CAA-01's acceptance criterion doesn't require it. | `docs/architecture.md` D4 |
| D7 | ~~LOW~~ | ~~**CT-03's unobserved-issuance match uses serial number only, not SHA-256 fingerprint.** Filed 2026-09-25 at D3's design, §Non-goals. crt.sh's JSON rows don't carry a fingerprint or full DER; fetching either costs one extra request per issuance, which at crt.sh's real 5 req/min throttle (verified 2026-09-25) would dominate every audit's runtime. Fix shape: fetch full DER (`https://crt.sh/?d=<id>`) and compare SHA-256, behind a flag, once real audits show serial-only matching produces false results. Not done now — no evidence yet that serial-number collision across issuers is a real risk at this scale.~~ (Originally filed against `docs/architecture.md` D3.) **Closed 2026-09-25 by D8** as an opt-in: `--ct-fetch-der` fetches the DER of each final-certificate entry matched on (issuer, serial) and requires a SHA-256 match (`CT_FINGERPRINT_MISMATCH` otherwise). It is off by default for the throttle reason above. Precertificate DER can never match (poison extension), so those entries are skipped. | `audit/ct/CtReconciler.java` |

## Bucket 2 — Found during D8's implementation (2026-09-25)

| # | Severity | Item | Where |
|---|---|---|---|
| D9 | MED | **CHN-03's trust anchors are whatever trust store the running JDK has, so the same chain can pass on one machine and fail on another.** Filed 2026-09-25 (D8 F13). Debian's `/etc/ssl/certs/java/cacerts` (144 anchors) no longer holds Comodo *AAA Certificate Services*, which Oracle's store still holds. The report names the store and its anchor count, so a result can be traced, but two auditors on different distros can disagree. Fix shape: bundle a dated Mozilla/CCADB root snapshot and use it instead of `cacerts`. This overlaps with CHN-04's client profiles, which need the same data. | `audit/served/TrustAnchors.java` |
| D10 | LOW | **`-audit` always exits 0.** Filed 2026-09-25. `AuditCommand.execute` returns 2 when a check failed and 1 on an input error, but `CertManager.parseAndExecute` discards the value, since calling `System.exit` there would kill the existing `CertManagerTest` JVM. That doesn't matter for manual runs; it matters once a script or CI job runs audits. Fix shape: `main` exits with a code returned by `parseAndExecute`. | `CertManager.java`, `audit/AuditCommand.java` |
| D11 | MED | **D8's field acceptance items 1 and 3 are open.** Filed 2026-09-25. Nothing about crt.sh answer parsing, `%.domain` subdomain coverage or `(issuer, serial)` matching against real CT data has run on a real response: crt.sh answered 502 to every request that day. Close item 3 by running `-audit` on a domain you own when crt.sh is up and comparing the issuance count with a manual `https://crt.sh/?q=%25.<domain>` search. Close item 1 with a three-domain run. Until then, CT results in a paid audit should be spot-checked by hand. | `docs/architecture.md` D8 §Acceptance gate |

## Phase 0 gate

From `Monitor360/Monitor360-Certificate-Verification-Requirements.md` §8.

| Gate item | Status |
|---|---|
| IBM outside-work approval before any paid engagement | **Confirmed 2026-09-25**, as stated by the user in session. No approval document is held in this repo. |
| Three audits offered | Open |
| At least one audit paid | Open (this is the H5 willingness-to-pay test) |

## Sequencing

D1 (CLI verb, `Finding`/`DomainAuditResult` shape, CSV input, report export) must land before
D2/D3/D4 are individually testable end-to-end, since each of them plugs into `AuditRunner` and the
report writer D1 defines — but D2, D3 and D4's own internal logic (served-state probing, CT
reconciliation, CAA resolution) has no dependency on each other and can be built and unit-tested in
any order or in parallel.
