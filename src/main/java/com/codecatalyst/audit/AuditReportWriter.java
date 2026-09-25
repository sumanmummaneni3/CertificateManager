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
import com.codecatalyst.audit.caa.CaaProperty;
import com.codecatalyst.audit.caa.CaaResolution;
import com.codecatalyst.audit.served.AddressObservation;
import com.codecatalyst.audit.served.CertSummary;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Writes one run's four outputs (D8): the JSON export (also the next run's {@code --baseline}),
 * the findings CSV, the coverage CSV, and the Markdown report filled from the template.
 */
public final class AuditReportWriter {

    public record Written(Path json, Path findingsCsv, Path coverageCsv, Path report) {}

    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);

    private AuditReportWriter() {}

    public static ObjectMapper mapper() {
        SimpleModule time = new SimpleModule();
        time.addSerializer(Instant.class, ToStringSerializer.instance);
        return new ObjectMapper().registerModule(time).enable(SerializationFeature.INDENT_OUTPUT);
    }

    public static Written write(AuditReport r, Path dir) throws IOException {
        Files.createDirectories(dir);
        String base = "audit-" + STAMP.format(r.meta().startedAt());
        Path json = dir.resolve(base + ".json");
        Path findings = dir.resolve(base + "-findings.csv");
        Path coverage = dir.resolve(base + "-coverage.csv");
        Path report = dir.resolve(base + "-report.md");
        mapper().writeValue(json.toFile(), r);
        Files.writeString(findings, findingsCsv(r), StandardCharsets.UTF_8);
        Files.writeString(coverage, coverageCsv(r), StandardCharsets.UTF_8);
        Files.writeString(report, markdown(r, json.getFileName().toString(), findings.getFileName().toString()),
                StandardCharsets.UTF_8);
        return new Written(json, findings, coverage, report);
    }

    static String findingsCsv(AuditReport r) {
        StringBuilder sb = new StringBuilder("ct_domain,host,type,severity,subject,detail,why,remediation,evidence,observed_at\n");
        for (Finding f : r.findings()) {
            sb.append(csv(f.ctDomain(), f.host(), f.type(), f.severity().name(), f.subject(), f.detail(), f.why(),
                    f.remediation(), f.evidence(), String.valueOf(f.observedAt()))).append('\n');
        }
        return sb.toString();
    }

    static String coverageCsv(AuditReport r) {
        StringBuilder sb = new StringBuilder("subject,check,status,message\n");
        for (CheckStatus c : r.coverage()) {
            sb.append(csv(c.subject(), c.check(), c.status().name(), c.message())).append('\n');
        }
        return sb.toString();
    }

    static String markdown(AuditReport r, String jsonName, String findingsName) throws IOException {
        String t;
        try (InputStream in = AuditReportWriter.class.getResourceAsStream("/audit-report-template.md")) {
            if (in == null) throw new IOException("audit-report-template.md missing from the classpath");
            t = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        var m = r.meta();
        Map<String, String> v = new LinkedHashMap<>();
        v.put("CLIENT", "TODO (hand-written): client name");
        v.put("VERSION", m.version());
        v.put("STARTED_AT", String.valueOf(m.startedAt()));
        v.put("FINISHED_AT", String.valueOf(m.finishedAt()));
        v.put("REQUESTER", md(m.requester()));
        v.put("BASIS", m.basis());
        v.put("TARGET_COUNT", String.valueOf(r.targets().size()));
        v.put("CSV", md(m.csv()));
        v.put("RESOLVER", md(m.resolver()));
        v.put("TRUST_ANCHORS", md(m.trustAnchors()));
        v.put("JSON_FILE", jsonName);
        v.put("FINDINGS_CSV", findingsName);
        v.put("SEVERITY_COUNTS", severityCounts(r));
        v.put("COVERAGE_GAPS", coverageGaps(r));
        v.put("UNOBSERVED", unobserved(r));
        v.put("CAA", caa(r));
        v.put("SERVED", served(r));
        v.put("OWNERSHIP_GAPS", ownership(r));
        v.put("INVENTORY", inventory(r));
        v.put("ROW_ERRORS", rowErrors(r));
        for (var e : v.entrySet()) t = t.replace("{{" + e.getKey() + "}}", e.getValue());
        return t;
    }

    private static String severityCounts(AuditReport r) {
        StringBuilder sb = new StringBuilder("| Severity | Findings |\n|---|---|\n");
        for (Severity s : Severity.values()) {
            sb.append("| ").append(s).append(" | ").append(r.findings().stream().filter(f -> f.severity() == s).count()).append(" |\n");
        }
        return sb.toString();
    }

    private static String coverageGaps(AuditReport r) {
        // Every non-OK row, plus OK rows that carry a qualification (partial reach, a CT source that
        // failed, unreachable endpoints not compared); a ct:<source> row's OK message is only its fetch
        // time, so it is left out.
        List<CheckStatus> gaps = r.coverage().stream()
                .filter(c -> c.status() != CheckStatus.Status.OK || (!c.message().isEmpty() && !c.check().startsWith("ct:")))
                .toList();
        if (gaps.isEmpty()) return "Every check ran for every subject.\n";
        StringBuilder sb = new StringBuilder("| Subject | Check | Status | Message |\n|---|---|---|---|\n");
        for (CheckStatus c : gaps) {
            sb.append("| ").append(md(c.subject())).append(" | ").append(c.check()).append(" | ").append(c.status())
                    .append(" | ").append(md(c.message())).append(" |\n");
        }
        return sb.toString();
    }

    private static String unobserved(AuditReport r) {
        StringBuilder sb = new StringBuilder();
        if (r.ct().isEmpty()) sb.append("No CT results: see section 1's list of checks that did not run.\n\n");
        else {
            sb.append("| CT domain | Scope | Issuances logged | Valid now | Served by an audited endpoint | Sources that answered |\n|---|---|---|---|---|---|\n");
            for (CtDomainResult d : r.ct()) {
                String sources = d.sources().stream()
                        .map(a -> a.source() + " (" + (a.fromCache() ? "cache, " : "live, ") + a.fetchedAt() + ")")
                        .collect(Collectors.joining("; "));
                sb.append("| ").append(md(d.ctDomain())).append(" | ").append(d.scope()).append(" | ")
                        .append(d.issuances().size()).append(" | ").append(d.currentlyValid()).append(" | ")
                        .append(d.matched()).append(" | ").append(md(sources)).append(" |\n");
            }
            sb.append("\nCert Spotter returns only unexpired certificates, so the logged count includes expired ones only "
                    + "from crt.sh. Findings judge only certificates valid now.\n");
            sb.append('\n');
        }
        sb.append(findingTable(r, Set.of("UNOBSERVED_ISSUANCE", "CT_FINGERPRINT_MISMATCH")));
        return sb.toString();
    }

    private static String caa(AuditReport r) {
        StringBuilder sb = new StringBuilder();
        if (!r.caa().isEmpty()) {
            sb.append("| Name | Found at | Records | DNSSEC |\n|---|---|---|---|\n");
            for (CaaResolution c : r.caa()) {
                String recs = c.records().isEmpty() ? "none" : c.records().stream()
                        .map(p -> (p.critical() ? "[critical] " : "") + p.tag() + " \"" + p.value() + "\"")
                        .collect(Collectors.joining("; "));
                sb.append("| ").append(md(c.queriedName())).append(" | ")
                        .append(c.foundAtName() == null ? "—" : md(c.foundAtName())).append(" | ").append(md(recs))
                        .append(" | ").append(c.dnssecStatus()).append(" |\n");
            }
            sb.append('\n');
        }
        sb.append(findingTable(r, Set.of("CAA_ABSENT", "CAA_NO_ACCOUNT_BINDING", "CAA_NO_METHOD_BINDING",
                "CAA_WILDCARD_UNRESTRICTED")));
        return sb.toString();
    }

    private static String served(AuditReport r) {
        Set<String> types = new HashSet<>(Set.of("NODE_DIVERGENCE", "CHAIN_CHANGED", "EXPIRED_SERVED_CERT",
                "EXPIRED_IN_CHAIN", "ROOT_INCLUDED", "WRONG_ORDER", "MISSING_INTERMEDIATE", "AIA_ONLY_COMPLETION",
                "WEAK_SIGNATURE", "WEAK_KEY"));
        return findingTable(r, types);
    }

    private static String findingTable(AuditReport r, Set<String> types) {
        List<Finding> fs = r.findings().stream().filter(f -> types.contains(f.type())).toList();
        if (fs.isEmpty()) return "No findings of these types (check the list of checks that did not run before reading this as clean).\n";
        StringBuilder sb = new StringBuilder();
        for (Finding f : fs) {
            sb.append("### ").append(f.severity()).append(" — ").append(f.type()).append(" — ").append(md(f.subject())).append("\n\n")
                    .append("- **Observed:** ").append(md(f.detail())).append('\n')
                    .append("- **Why it matters:** ").append(f.why()).append('\n')
                    .append("- **Remediation:** ").append(f.remediation()).append('\n')
                    .append("- **Evidence:** ").append(md(f.evidence())).append(" (").append(f.observedAt()).append(")\n\n");
        }
        return sb.toString();
    }

    private static String ownership(AuditReport r) {
        List<AuditTarget> unowned = r.targets().stream().filter(t -> t.owner() == null || t.owner().isBlank()).toList();
        if (unowned.isEmpty()) return "Every audited host:port has an owner in the input.\n";
        StringBuilder sb = new StringBuilder("These rows have no owner in the input:\n\n");
        for (AuditTarget t : unowned) sb.append("- ").append(md(t.hostPort())).append('\n');
        return sb.toString();
    }

    private static String inventory(AuditReport r) {
        Map<String, AuditTarget> byHostPort = new HashMap<>();
        r.targets().forEach(t -> byHostPort.put(t.hostPort(), t));
        StringBuilder sb = new StringBuilder("| Host:port | Address | Owner | Leaf subject | Issuer | Expires | Protocol | Status |\n|---|---|---|---|---|---|---|---|\n");
        for (AddressObservation o : r.observations()) {
            AuditTarget t = byHostPort.get(o.host() + ":" + o.port());
            String owner = t == null ? "" : t.owner();
            if (!o.reachable()) {
                sb.append("| ").append(md(o.host() + ":" + o.port())).append(" | ").append(o.address()).append(" | ")
                        .append(md(owner)).append(" | — | — | — | — | unreachable: ").append(md(o.error())).append(" |\n");
                continue;
            }
            CertSummary leaf = r.certificates().get(o.leafSha256());
            sb.append("| ").append(md(o.host() + ":" + o.port())).append(" | ").append(o.address()).append(" | ")
                    .append(md(owner)).append(" | ").append(md(leaf.subject())).append(" | ").append(md(leaf.issuer()))
                    .append(" | ").append(leaf.notAfter()).append(" | ").append(o.protocol()).append(" | served |\n");
        }
        return sb.toString();
    }

    private static String rowErrors(AuditReport r) {
        if (r.rowErrors().isEmpty()) return "None.\n";
        StringBuilder sb = new StringBuilder("| Line | Reason | Row |\n|---|---|---|\n");
        for (var e : r.rowErrors()) {
            sb.append("| ").append(e.line()).append(" | ").append(md(e.reason())).append(" | `")
                    .append(e.rawLine().replace("`", "'").replace("|", "\\|")).append("` |\n");
        }
        return sb.toString();
    }

    /**
     * Markdown table cells: no pipes, no line breaks, and no live HTML, since error bodies (crt.sh's
     * 502 page) and CAA values arrive as received and a Markdown viewer would render the tags.
     */
    static String md(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("|", "\\|").replaceAll("[\\r\\n]+", " ");
    }

    /**
     * One CSV row; every field quoted, since details and remediation text contain commas. A field
     * starting with a formula character is prefixed with an apostrophe: CAA values and CT names come
     * from DNS and logs the audited party controls, and this file is meant to be opened in Excel.
     */
    static String csv(String... fields) {
        return Arrays.stream(fields)
                .map(f -> f == null ? "" : f.replaceAll("[\\r\\n]+", " "))
                .map(f -> !f.isEmpty() && "=+-@\t".indexOf(f.charAt(0)) >= 0 ? "'" + f : f)
                .map(f -> "\"" + f.replace("\"", "\"\"") + "\"")
                .collect(Collectors.joining(","));
    }
}
