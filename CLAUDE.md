# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Scope note

A broader `CLAUDE.md` exists at `/home/msuman/git/CLAUDE.md` describing a different monorepo
(CertGuard and friends) and a `Monitor360/CLAUDE.md` describing the Monitor360 platform. **This is
neither** — CertificateManager is a standalone, single-module Gradle CLI tool with no Spring Boot,
no database beyond a local PKCS12 keystore, and no server component. Prefer this file for anything
under this repo.

## What this is

A lightweight, single-JVM-process CLI (`com.codecatalyst.CertManager`, `main` in
`src/main/java/com/codecatalyst/CertManager.java`) that discovers and inventories X.509
certificates by connecting directly to hosts — no agent, no server, no account system. State is a
local PKCS12 keystore at `~/.certmgr/keystore.p12` (see `PathManager`/`PersistenceManager`),
readable only by whoever runs the CLI.

**Why this repo exists as a Monitor360 sibling, not a Monitor360 module:** it is Phase 0 of the
Certificate Verification Layer initiative (see
`Monitor360/Monitor360-Certificate-Verification-Requirements.md` §8 for the full phasing) —
deliberately built *outside* the Monitor360 platform so the audit-kit work can validate paid
demand (H5) before any further platform investment. D-numbers here are a separate sequence from
Monitor360's; this repo starts at D1.

## Build and test

**`JAVA_HOME` must point at JDK 17 to run Gradle at all on this machine** — see gotcha 0.

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64   # or prefix every command below with it
./gradlew clean build      # compile, test, produce the runnable jar + lib/ dependency folder
./gradlew test              # run the JUnit 5 suite
./gradlew test --tests "com.codecatalyst.CertManagerTest"   # single test class
./gradlew run --args="-scan example.com"                    # run without building a jar first
```

There is no Docker, no database server, no integration-test tier — every test in this repo is a
fast, in-process JUnit 5 unit test. `./gradlew build` should stay that way; if a Phase 0 feature
needs a slower, opt-in verification tier (e.g. a real DNS/network round trip against a live CT
log), gate it behind a Gradle test tag rather than letting it block `build`.

## Architecture

```
CertManager (CLI entry, arg parsing + dispatch)
  ├─ net/FetchCertificates    — one TLS handshake, returns the peer certificate chain
  ├─ net/NetworkScanner       — parallel multi-target scan (ExecutorService); currently unused by
  │                             CertManager's own dispatch, which scans sequentially instead — see
  │                             gotcha 2
  ├─ net/NetUtils             — pure IP-range arithmetic (BigInteger <-> InetAddress)
  ├─ persist/PersistenceManager — PKCS12 keystore CRUD, alias = host or host_port
  ├─ persist/PathManager       — resolves ~/.certmgr, creates it if missing
  ├─ service/NinjaScanner      — expiry-status JSON for NinjaOne agent integration
  ├─ common/{CertConstants,CommandParamsEnum} — constants, CLI verb enum
  └─ audit/                    — Phase 0 audit kit, the `-audit` verb (D1–D4 as amended by D8)
       ├─ AuditCommand / AuditOptions / AuditRunner / AuditReportWriter — wiring, flags, orchestration, 4 outputs
       ├─ CsvTargetReader, FindingCatalog (severity + why + remediation per type), CheckStatus (coverage)
       ├─ served/  — ServedStateProber (VER-01), ChainAnalyzer (VER-02, CHN-02/03), TrustAnchors
       ├─ ct/      — CrtShSource + CertSpotterSource (D14) behind CtLogSource; CtCache, RateGate,
       │             HttpFetcher; CtReconciler (CT-02/03, SHA-256 match when a source gives it), IssuerNames
       └─ caa/     — CaaResolver (RFC 8659 climb), DnsjavaCaaQuerier, CaaEvaluator (CAA-02)
```

Every network dependency of the audit kit sits behind a functional interface (`HostResolver`,
`Handshaker`, `HttpFetcher`, `CaaQuerier`, `CtLogSource`), so the whole kit is unit-tested with
no network. `src/test/resources/ct/` holds one **real** recorded Cert Spotter response and
example.com's real served leaf (both captured 2026-09-25), so parsing and SHA-256 matching are
tested against real data, not only hand-written JSON. Test certificates come from `src/test/.../audit/TestCerts.java` (BouncyCastle, test
scope only). Its keys are generated once per JVM, because RSA key generation is slow.

No CLI argument-parsing library — `CommandParamsEnum` plus hand-rolled array scanning in
`CertManager`. No DI framework, no config file, options are `--port`/`--range` CLI flags only.

## Gotchas

0. **Gradle 8.14 (this repo's wrapper version) cannot run under this machine's default JDK
   (25.0.3) at all — not a compile-target issue, a Gradle-itself-won't-start issue.** Two
   independent failures, both confirmed: with the original Kotlin-DSL `settings.gradle.kts`,
   Gradle's embedded Kotlin compiler throws `IllegalArgumentException: 25.0.3` from
   `JavaVersion.parse` (it can't parse a 3-component version string) while evaluating the
   settings script; converting to a plain-Groovy `settings.gradle` sidesteps that but then
   Gradle's own Groovy compiler fails on `build.gradle` itself with `Unsupported class file major
   version 69` (69 = Java 25's class-file version) — so the plain-Groovy build script Gradle
   itself is written to interpret is compiled against a class-file version this Gradle's bundled
   Groovy can't read either. Neither is a project misconfiguration; it's Gradle 8.14 not
   supporting JDK 25 as the JVM that *runs* Gradle. **The fix is `JAVA_HOME=/usr/lib/jvm/java-17-
   openjdk-amd64` for every `./gradlew` invocation** (confirmed: `compileJava`, `compileTestJava`,
   `test` all succeed under it) — do not "fix" this by rewriting `settings.gradle.kts` to Groovy
   (reverted; it doesn't fully solve it, and Kotlin DSL isn't the actual problem) or by adding a
   Gradle Java toolchain block (that controls what JDK compiles the *project's* code, not what JDK
   Gradle itself boots on — a different, unrelated lever). Upgrading the Gradle wrapper to a
   version with real JDK 25 support is the durable fix if this becomes a recurring friction point;
   not done here since it's out of Phase 0's scope and untested against this project's actual
   dependency set.
1. **`FetchCertificates.fetchCertMetadata()` returns only the leaf; `fetchHandshake()` (added by
   D8) returns the full served chain plus protocol and cipher, and is what the audit kit uses.**
   The `-scan` inventory path still stores leaves only. The trust-all `TrustManager` is deliberate and correct for this tool's purpose
   (it must inspect certificates regardless of whether they're trusted) — do not "fix" it into a
   real trust check, that would break scanning self-signed/internal hosts, which is half the
   tool's use case.
2. **`PersistenceManager.saveCertificate(String, X509Certificate[])` — a full-chain-aware overload
   — already exists and is unused.** `CertConstants.LEAF`/`CHAIN_CERT` alias suffixes exist for
   it. `NetworkScanner` (the parallel-scan class) is also currently dead code — nothing in
   `CertManager`'s dispatch calls it; `CertManager.scanAndStore`/`scanRange` scan sequentially
   instead. Both look like a chain-storage feature that was half-built and never wired in. The audit
   kit deliberately uses neither (D2 F2/F3): audit evidence goes to the run's JSON export, never to
   the keystore, and `ServedStateProber` replaced `NetworkScanner` for per-address probing.
3. **SNI is sent automatically.** `FetchCertificates` calls
   `factory.createSocket(socket, host, port, true)` — the JSSE default for this overload sets the
   SNI `server_name` extension from the `host` parameter. Do not add an explicit
   `SSLParameters.setServerNames` call assuming SNI is currently missing; it isn't.
4. **Only the audit kit resolves every address.** `ServedStateProber` calls
   `InetAddress.getAllByName` and handshakes with each A/AAAA address. The `-scan` path still makes
   one handshake to whatever address the OS resolver picks first.
5. **The keystore password is a hardcoded literal (`CertConstants.PASSWORD = "changeit"`).** This
   predates Phase 0 and protects only local file-permission-level secrecy (no PII/private key
   material is stored — public certificates only). Out of Phase 0's scope; not a design blocker,
   but do not copy this pattern into any new secret-bearing code path Phase 0 adds (e.g. a CT API
   key, if one is ever needed) — see backlog.
6. **CHN-03's anchor walk must stop at the first certificate that is, or is signed by, a trust
   anchor (D8 F13).** The reflex version walks the served chain to its end and asks the anchors about
   the last certificate. On example.com (2026-09-25) that walks past *SSL.com TLS ECC Root CA 2022*,
   an anchor, into its cross-sign from Comodo *AAA Certificate Services*, which Debian's trust store
   has dropped. Every address then reports `MISSING_INTERMEDIATE` for a correct chain, with no error.
   The anchors are the running JDK's `cacerts`, so results can differ between machines (backlog D9).
   The report states which store was used.
7. **Every CT source failure is reported exactly as received, per source, and must never read as
   "no issuances" (D8 F9, D14).** There are two sources, crt.sh and Cert Spotter, queried side by
   side (`--ct-sources`). Each writes its own coverage row, `ct:crt.sh` or `ct:certspotter`. After a
   failure (one retry on a 5xx, none on a 4xx or 429), that row is `ERROR` with the status and body,
   e.g. nginx's 502 page. `ct03` is `NOT_CHECKED` only when **no** source answered; otherwise it is
   `OK` and says which sources it compared against. Do not catch a failure and return an empty list:
   the report would then say "no unobserved issuance". Failures are never written to `CtCache`, and a
   200 with a non-JSON body is an error, not an empty result. Cert Spotter stops for the rest of the
   run after its first 429 (anonymous quota: 10 requests, about 5 domains an hour, backlog D15). Its
   API key comes **only** from the environment variable `CERTSPOTTER_API_KEY`: never a flag (shell
   history, `ps`), never a file, never in a URL, cache key or error message.
8. **`UNOBSERVED_ISSUANCE` only judges certificates valid at run time, against every leaf served in
   the run (D8 F2/F3).** A one-shot CLI has no served history. Comparing *all* logged issuances would
   flag every past renewal (about six a year for a Let's Encrypt name), and comparing per CSV row would
   flag a sibling host's certificate. Both are false-positive floods that look like real findings.
9. **`CAA_NO_ACCOUNT_BINDING`/`CAA_NO_METHOD_BINDING` skip issue values with an empty CA domain
   (D8 F6).** `issue ";"` forbids all issuance. Flagging it for "no accounturi" tells a client that
   their strictest possible setting is a gap.
