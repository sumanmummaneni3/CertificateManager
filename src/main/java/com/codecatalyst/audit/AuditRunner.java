/*
 * Copyright (c) 2026 CodeCatalyst
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codecatalyst.audit;

import com.codecatalyst.audit.AuditReport.CtDomainResult;
import com.codecatalyst.audit.caa.CaaEvaluator;
import com.codecatalyst.audit.caa.CaaLookupException;
import com.codecatalyst.audit.caa.CaaResolution;
import com.codecatalyst.audit.caa.CaaResolver;
import com.codecatalyst.audit.ct.*;
import com.codecatalyst.audit.served.*;

import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * Runs every Phase 0 check for a set of targets and assembles one {@link AuditReport} (D1, amended
 * by D8). Each check fails on its own: an error is recorded in coverage with its message as
 * received and never stops another check or another target.
 */
public class AuditRunner {

    private final ServedStateProber prober;
    private final CaaResolver caa;
    private final List<CtLogSource> ctSources;
    private final List<String> ctUnselected;
    private final TrustAnchors anchors;
    private final Clock clock;
    private final int concurrency;
    private final boolean ctFetchDer;

    /**
     * @param ctSources    the CT sources to query, in order (D14)
     * @param ctUnselected names of known sources left out by {@code --ct-sources}, recorded as NOT_CHECKED
     */
    public AuditRunner(ServedStateProber prober, CaaResolver caa, List<CtLogSource> ctSources,
                       List<String> ctUnselected, TrustAnchors anchors, Clock clock, int concurrency,
                       boolean ctFetchDer) {
        this.prober = prober;
        this.caa = caa;
        this.ctSources = List.copyOf(ctSources);
        this.ctUnselected = List.copyOf(ctUnselected);
        this.anchors = anchors;
        this.clock = clock;
        this.concurrency = concurrency;
        this.ctFetchDer = ctFetchDer;
    }

    public AuditReport run(List<AuditTarget> targets, List<CsvTargetReader.RowError> rowErrors,
                           BaselineLoader.Baseline baseline, AuditReport.RunMeta metaTemplate)
            throws InterruptedException {
        Instant started = clock.instant();
        List<Finding> findings = new ArrayList<>();
        List<CheckStatus> coverage = new ArrayList<>();
        Map<String, CertSummary> certs = new TreeMap<>();
        Map<AuditTarget, List<AddressObservation>> byTarget = probeAll(targets, coverage);

        List<AddressObservation> allObs = new ArrayList<>();
        for (AuditTarget t : targets) {
            List<AddressObservation> obs = byTarget.getOrDefault(t, List.of());
            allObs.addAll(obs);
            for (AddressObservation o : obs) {
                if (!o.reachable()) continue;
                for (X509Certificate c : o.chain()) certs.putIfAbsent(CertFingerprints.sha256(c), CertSummary.of(c));
                findings.addAll(ChainAnalyzer.detectChainDefects(t.ctDomain(), o, anchors, started));
            }
            ChainAnalyzer.detectNodeDivergence(t.ctDomain(), obs).ifPresent(findings::add);
            chainChange(t, obs, baseline, certs, findings, coverage);
        }

        List<CaaResolution> caaResults = new ArrayList<>();
        Map<String, AuditTarget> caaHosts = new LinkedHashMap<>();
        for (AuditTarget t : targets) caaHosts.putIfAbsent(t.host(), t);
        for (AuditTarget t : caaHosts.values()) {
            if (isIpLiteral(t.host())) {
                // RFC 8659 covers domain names only; climbing an IP's octets would report a false CAA_ABSENT (D12)
                coverage.add(CheckStatus.notChecked(t.host(), "caa", "CAA does not apply to IP addresses"));
                continue;
            }
            try {
                CaaResolution r = caa.resolve(t.host());
                caaResults.add(r);
                findings.addAll(CaaEvaluator.evaluate(t.ctDomain(), r));
                coverage.add(CheckStatus.ok(t.host(), "caa"));
            } catch (CaaLookupException e) {
                coverage.add(CheckStatus.error(t.host(), "caa", e.getMessage()));
            }
        }

        List<CtDomainResult> ctResults = ctAll(targets, byTarget, allObs, started, findings, coverage);

        AuditReport.RunMeta m = metaTemplate;
        AuditReport.RunMeta meta = new AuditReport.RunMeta(m.tool(), m.version(), started, clock.instant(),
                m.requester(), m.basis(), m.csv(), m.baseline(), m.resolver(), anchors.source() + ", "
                + anchors.size() + " anchors", m.ctCacheTtlHours(), m.ctFetchDer(), m.ctSources(), m.certSpotterAuth());
        findings.sort(Comparator.comparing(Finding::severity).thenComparing(Finding::ctDomain)
                .thenComparing(Finding::host).thenComparing(Finding::type));
        return new AuditReport(meta, targets, rowErrors, allObs, certs, ctResults, caaResults, findings, coverage);
    }

    private Map<AuditTarget, List<AddressObservation>> probeAll(List<AuditTarget> targets, List<CheckStatus> coverage)
            throws InterruptedException {
        ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, concurrency));
        try {
            Map<AuditTarget, Future<List<AddressObservation>>> futures = new LinkedHashMap<>();
            for (AuditTarget t : targets) futures.put(t, pool.submit(() -> prober.probe(t.host(), t.port())));
            Map<AuditTarget, List<AddressObservation>> out = new LinkedHashMap<>();
            for (var e : futures.entrySet()) {
                AuditTarget t = e.getKey();
                try {
                    List<AddressObservation> obs = e.getValue().get();
                    out.put(t, obs);
                    coverage.addAll(verStatus(t, obs));
                } catch (ExecutionException ex) {
                    Throwable c = ex.getCause();
                    String msg = (c instanceof UnknownHostException)
                            ? "DNS resolution failed: " + c.getMessage()
                            : c.getClass().getSimpleName() + ": " + c.getMessage();
                    coverage.add(CheckStatus.error(t.hostPort(), "ver", msg));
                }
            }
            return out;
        } finally {
            pool.shutdownNow();
        }
    }

    /**
     * VER coverage (D8, made explicit at design audit): one row per host:port, plus one ERROR row per
     * unreachable address with its error as received. A partial result is never an OK row that only a
     * free-text message qualifies; the per-address rows count as failed checks.
     */
    static List<CheckStatus> verStatus(AuditTarget t, List<AddressObservation> obs) {
        if (obs.isEmpty()) return List.of(CheckStatus.error(t.hostPort(), "ver", "the name resolved to no addresses"));
        List<CheckStatus> out = new ArrayList<>();
        long reached = obs.stream().filter(AddressObservation::reachable).count();
        if (reached == 0) {
            out.add(CheckStatus.error(t.hostPort(), "ver", "every address unreachable (" + obs.size() + ")"));
        } else if (reached < obs.size()) {
            out.add(new CheckStatus(t.hostPort(), "ver", CheckStatus.Status.OK,
                    reached + " of " + obs.size() + " addresses reached; each unreachable address has its own ERROR row"));
        } else {
            out.add(CheckStatus.ok(t.hostPort(), "ver"));
        }
        for (AddressObservation o : obs) {
            if (!o.reachable()) out.add(CheckStatus.error(o.subject(), "ver", o.error()));
        }
        return out;
    }

    static boolean isIpLiteral(String host) {
        return host.matches("\\d{1,3}(\\.\\d{1,3}){3}") || host.contains(":");
    }

    private static void chainChange(AuditTarget t, List<AddressObservation> obs, BaselineLoader.Baseline baseline,
                                    Map<String, CertSummary> certs, List<Finding> findings, List<CheckStatus> coverage) {
        if (baseline == null) {
            coverage.add(CheckStatus.notChecked(t.hostPort(), "chn02", "no --baseline given"));
            return;
        }
        List<BaselineObservation> sameHostPort = baseline.observations().stream()
                .filter(b -> b.host().equals(t.host()) && b.port() == t.port()).toList();
        if (sameHostPort.isEmpty()) {
            coverage.add(CheckStatus.notChecked(t.hostPort(), "chn02", "not in baseline " + baseline.source()));
            return;
        }
        Map<String, String> subjects = new HashMap<>(baseline.subjectBySha());
        certs.values().forEach(c -> subjects.put(c.sha256(), c.subject()));
        boolean compared = false;
        for (AddressObservation o : obs) {
            if (!o.reachable()) continue;
            List<BaselineObservation> sameLeaf = sameHostPort.stream()
                    .filter(b -> b.leafSha256().equals(o.leafSha256())).toList();
            if (sameLeaf.isEmpty()) continue;
            compared = true;
            ChainAnalyzer.detectChainChanged(t.ctDomain(), o, sameLeaf, subjects).ifPresent(findings::add);
        }
        coverage.add(compared
                ? CheckStatus.ok(t.hostPort(), "chn02")
                : CheckStatus.notChecked(t.hostPort(), "chn02",
                "no reachable address serves a leaf seen in the baseline (renewed, or unreachable now)"));
    }

    private List<CtDomainResult> ctAll(List<AuditTarget> targets, Map<AuditTarget, List<AddressObservation>> byTarget,
                                       List<AddressObservation> allObs, Instant now, List<Finding> findings,
                                       List<CheckStatus> coverage) throws InterruptedException {
        Map<String, List<AuditTarget>> byDomain = new LinkedHashMap<>();
        for (AuditTarget t : targets) byDomain.computeIfAbsent(t.ctDomain(), k -> new ArrayList<>()).add(t);

        // Any leaf served anywhere in the run counts as observed: a multi-SAN certificate for this
        // domain may be served on a host listed under another one.
        List<CtReconciler.ServedLeaf> served = new ArrayList<>();
        for (AddressObservation o : allObs) {
            if (o.reachable()) served.add(new CtReconciler.ServedLeaf(o.chain()[0], o.leafSha256(), o.evidence()));
        }

        // CT-03 compares against the whole run, so an unreachable endpoint anywhere could be the one
        // serving an issuance; the ct03 row names them rather than implying full coverage (D13).
        List<String> unreachable = allObs.stream().filter(o -> !o.reachable()).map(AddressObservation::subject).toList();

        CtReconciler.DerFetcher der = null;
        if (ctFetchDer) {
            for (CtLogSource src : ctSources) {
                if (src instanceof CrtShSource crtSh) der = crtSh::fetchDer;
            }
        }

        List<CtDomainResult> out = new ArrayList<>();
        for (var e : byDomain.entrySet()) {
            String domain = e.getKey();
            List<AuditTarget> ts = e.getValue();
            String scope = ts.stream().anyMatch(t -> t.domain() != null) ? "DOMAIN" : "HOST_ONLY";
            List<String> hosts = ts.stream().map(AuditTarget::hostPort).toList();

            // Every selected source is asked; one failing never stops the other (D14).
            List<CtEntry> entries = new ArrayList<>();
            List<AuditReport.SourceAnswer> answered = new ArrayList<>();
            List<String> failed = new ArrayList<>();
            for (CtLogSource src : ctSources) {
                String check = "ct:" + src.name();
                try {
                    CtFetchResult r = src.fetch(domain);
                    entries.addAll(r.entries());
                    answered.add(new AuditReport.SourceAnswer(src.name(), r.fetchedAt(), r.fromCache(), r.urls(),
                            r.entries().size()));
                    coverage.add(new CheckStatus(domain, check, CheckStatus.Status.OK,
                            (r.fromCache() ? "cached answer fetched " : "fetched ") + r.fetchedAt()
                                    + ("HOST_ONLY".equals(scope) ? "; scope HOST_ONLY (no domain column)" : "")));
                } catch (CtLookupException ex) {
                    failed.add(src.name());
                    coverage.add(CheckStatus.error(domain, check, ex.getMessage()));
                }
            }
            for (String name : ctUnselected) {
                coverage.add(CheckStatus.notChecked(domain, "ct:" + name, "not selected by --ct-sources"));
            }
            if (answered.isEmpty()) {
                coverage.add(CheckStatus.notChecked(domain, "ct03",
                        "no CT source answered, so unobserved issuance was not checked"));
                continue;
            }
            List<CtIssuance> issuances = CtReconciler.reconcile(entries);
            Instant fetchedAt = answered.stream().map(AuditReport.SourceAnswer::fetchedAt)
                    .min(Comparator.naturalOrder()).orElseThrow();

            boolean anyReachable = ts.stream()
                    .flatMap(t -> byTarget.getOrDefault(t, List.of()).stream())
                    .anyMatch(AddressObservation::reachable);
            if (!anyReachable) {
                coverage.add(CheckStatus.notChecked(domain, "ct03",
                        "no audited endpoint under this domain was reachable, so served state cannot be compared"));
                out.add(new CtDomainResult(domain, scope, hosts, issuances, answered,
                        (int) issuances.stream().filter(i -> i.validAt(now)).count(), 0));
                continue;
            }
            CtReconciler.Outcome oc = CtReconciler.detectUnobserved(domain, issuances, served, now, fetchedAt, der);
            findings.addAll(oc.findings());
            List<String> qualifiers = new ArrayList<>();
            if (!failed.isEmpty()) {
                qualifiers.add("compared against " + String.join(" and ", answered.stream()
                        .map(AuditReport.SourceAnswer::source).toList()) + " only; " + String.join(" and ", failed)
                        + " failed (see its row)");
            }
            if (!unreachable.isEmpty()) {
                qualifiers.add("compared against reachable endpoints only; not compared: " + String.join(", ", unreachable));
            }
            coverage.add(qualifiers.isEmpty()
                    ? CheckStatus.ok(domain, "ct03")
                    : new CheckStatus(domain, "ct03", CheckStatus.Status.OK, String.join("; ", qualifiers)));
            if (!oc.derErrors().isEmpty()) {
                coverage.add(CheckStatus.error(domain, "ct-der", String.join(" | ", oc.derErrors())));
            }
            out.add(new CtDomainResult(domain, scope, hosts, issuances, answered, oc.currentlyValid(), oc.matched()));
        }
        return out;
    }
}
