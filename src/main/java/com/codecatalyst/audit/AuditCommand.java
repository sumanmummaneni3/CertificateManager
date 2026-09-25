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

import com.codecatalyst.audit.caa.CaaResolver;
import com.codecatalyst.audit.caa.DnsjavaCaaQuerier;
import com.codecatalyst.audit.ct.CertSpotterSource;
import com.codecatalyst.audit.ct.CrtShSource;
import com.codecatalyst.audit.ct.CtLogSource;
import com.codecatalyst.audit.ct.CtCache;
import com.codecatalyst.audit.ct.HttpFetcher;
import com.codecatalyst.audit.ct.RateGate;
import com.codecatalyst.audit.served.ServedStateProber;
import com.codecatalyst.audit.served.TrustAnchors;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static com.codecatalyst.persist.PathManager.getAppHome;

/** Wires the live dependencies for {@code -audit} and prints where the outputs went. */
public final class AuditCommand {

    public static final String VERSION = "1.1.0";
    public static final String USER_AGENT =
            "CertificateManager-Audit/" + VERSION + " (+https://github.com/sumanmummaneni3/CertificateManager)";
    private static final long CRT_SH_INTERVAL_MS = 12_500;
    // Cert Spotter's real limit is an hourly quota (10 anonymous); this only stops bursts (D14)
    private static final long CERT_SPOTTER_INTERVAL_MS = 1_000;
    /** The only way to give the kit a Cert Spotter API key: never a flag (shell history, ps) and never a file. */
    public static final String CERT_SPOTTER_KEY_ENV = "CERTSPOTTER_API_KEY";

    private AuditCommand() {}

    public static int execute(AuditOptions o) {
        Clock clock = Clock.systemUTC();
        try {
            CsvTargetReader.CsvReadResult csv = new CsvTargetReader().read(o.csv());
            for (var e : csv.errors()) System.err.println("CSV line " + e.line() + ": " + e.reason());
            if (csv.targets().isEmpty()) {
                System.err.println("Error: no usable rows in " + o.csv());
                return 1;
            }
            BaselineLoader.Baseline baseline = o.baseline() == null ? null : BaselineLoader.load(o.baseline());

            appendRunLog(o, csv.targets().size(), clock.instant());
            System.out.println("Auditing " + csv.targets().size() + " host:port rows (requester " + o.requester()
                    + ", basis " + o.basis() + "). crt.sh is rate-limited to one request every "
                    + CRT_SH_INTERVAL_MS / 1000.0 + "s, so CT takes about 25s per domain."
                    + (o.ctSources().contains("certspotter") && System.getenv(CERT_SPOTTER_KEY_ENV) == null
                    ? " Cert Spotter without " + CERT_SPOTTER_KEY_ENV + " allows about 5 domains an hour." : ""));

            CtCache cache = new CtCache(getAppHome().resolve("ct-cache"), Duration.ofHours(o.ctCacheTtlHours()), clock);
            HttpFetcher http = HttpFetcher.live(USER_AGENT);
            // Never follows redirects: it may carry the API key, which must not reach another host
            HttpFetcher certSpotterHttp = HttpFetcher.live(USER_AGENT, java.net.http.HttpClient.Redirect.NEVER);
            CertSpotterSource certSpotter = new CertSpotterSource(certSpotterHttp, new RateGate(CERT_SPOTTER_INTERVAL_MS), cache,
                    clock, System.getenv(CERT_SPOTTER_KEY_ENV));
            java.util.List<CtLogSource> sources = new java.util.ArrayList<>();
            java.util.List<String> unselected = new java.util.ArrayList<>();
            if (o.ctSources().contains("crtsh")) {
                sources.add(new CrtShSource(http, new RateGate(CRT_SH_INTERVAL_MS), cache, clock));
            } else {
                unselected.add(CrtShSource.NAME);
            }
            if (o.ctSources().contains("certspotter")) sources.add(certSpotter);
            else unselected.add(CertSpotterSource.NAME);
            CaaResolver caa = new CaaResolver(new DnsjavaCaaQuerier(o.resolver()), o.resolver(), clock);
            AuditReport report;
            try (ServedStateProber prober = ServedStateProber.live(o.concurrency())) {
                AuditRunner runner = new AuditRunner(prober, caa, sources, unselected, TrustAnchors.jdkDefault(), clock,
                        o.concurrency(), o.ctFetchDer());
                AuditReport.RunMeta meta = new AuditReport.RunMeta("CertificateManager", VERSION, null, null,
                        o.requester(), o.basis().name(), o.csv().toString(),
                        o.baseline() == null ? null : o.baseline().toString(), o.resolver(), null,
                        o.ctCacheTtlHours(), o.ctFetchDer(),
                        sources.stream().map(CtLogSource::name).toList(),
                        certSpotter.authenticated() ? "API_KEY" : "ANONYMOUS");
                report = runner.run(csv.targets(), csv.errors(), baseline, meta);
            }
            AuditReportWriter.Written w = AuditReportWriter.write(report, o.outDir());

            long errors = report.coverage().stream().filter(c -> c.status() == CheckStatus.Status.ERROR).count();
            System.out.println(report.findings().size() + " findings; " + errors + " checks failed (see coverage).");
            System.out.println("  " + w.json());
            System.out.println("  " + w.findingsCsv());
            System.out.println("  " + w.coverageCsv());
            System.out.println("  " + w.report());
            return errors == 0 ? 0 : 2;
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("Error: audit interrupted");
            return 1;
        }
    }

    /** RPT-02: every run leaves a line saying who ran it, on what basis, against what. */
    static void appendRunLog(AuditOptions o, int targetCount, Instant at) throws IOException {
        Path log = getAppHome().resolve("logs").resolve("audit-runs.log");
        Files.createDirectories(log.getParent());
        String line = at + "\trequester=" + o.requester().replaceAll("[\\t\\r\\n]", " ") + "\tbasis=" + o.basis()
                + "\tcsv=" + o.csv().toAbsolutePath() + "\ttargets=" + targetCount + System.lineSeparator();
        Files.writeString(log, line, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
}
