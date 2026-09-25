package com.codecatalyst.audit;

import com.codecatalyst.audit.served.AddressObservation;
import com.codecatalyst.audit.served.BaselineObservation;
import com.codecatalyst.audit.served.CertFingerprints;
import com.codecatalyst.audit.served.CertSummary;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static com.codecatalyst.audit.TestCerts.*;
import static org.junit.jupiter.api.Assertions.*;

class AuditReportWriterTest {

    private static final Chain C = TestCerts.chain();

    static AuditReport sample() {
        List<String> fps = List.of(CertFingerprints.sha256(C.leaf()), CertFingerprints.sha256(C.inter()));
        AddressObservation o = new AddressObservation("www.example.com", 443, "192.0.2.1", true, fps, fps.get(0),
                CertFingerprints.chainHash(fps), "TLSv1.3", "TLS_AES_128_GCM_SHA256", null, NOW,
                new java.security.cert.X509Certificate[]{C.leaf(), C.inter()});
        Finding f = Finding.of("CAA_NO_METHOD_BINDING", "example.com", "www.example.com", "www.example.com",
                "=HYPERLINK(\"http://evil\") issue \"ca, inc\" has no validationmethods", "caa www.example.com", NOW);
        return new AuditReport(
                new AuditReport.RunMeta("CertificateManager", "test", NOW, NOW, "Suman", "OWN", "t.csv", null, "8.8.8.8",
                        "test anchors", 6, false),
                List.of(new AuditTarget("www.example.com", 443, "example.com", "", Map.of(), 2)),
                List.of(new CsvTargetReader.RowError(3, "bad|row", "port out of range")),
                List.of(o),
                Map.of(fps.get(0), CertSummary.of(C.leaf()), fps.get(1), CertSummary.of(C.inter())),
                List.of(), List.of(), List.of(f),
                List.of(new CheckStatus("www.example.com:443", "ver", CheckStatus.Status.OK, "1 of 2 addresses reached; each unreachable address has its own ERROR row"),
                        CheckStatus.error("www.example.com:443@192.0.2.9", "ver", "SocketTimeoutException: Read timed out"),
                        CheckStatus.error("example.com", "ct", "crt.sh HTTP 502 for https://crt.sh/?q=example.com&output=json (attempt 2 of 2): <title>502 Bad Gateway</title>")));
    }

    @Test
    @DisplayName("Writes JSON, findings CSV, coverage CSV and a report with every placeholder filled")
    void writesFourFiles(@TempDir Path dir) throws Exception {
        AuditReportWriter.Written w = AuditReportWriter.write(sample(), dir);
        String md = Files.readString(w.report());
        assertFalse(md.contains("{{"), "unfilled placeholder in report");
        assertTrue(md.contains("crt.sh HTTP 502"), "CT failure appears in the report");
        assertTrue(md.contains("| 3 | port out of range | `bad\\|row` |"), "a pipe in the raw row cannot break the table");
        assertTrue(md.contains("TODO (hand-written)"));
        assertTrue(md.contains("| www.example.com:443@192.0.2.9 | ver | ERROR | SocketTimeoutException: Read timed out |"), "unreachable address listed as a gap");
        assertTrue(md.contains("1 of 2 addresses reached"), "qualified OK row listed as a gap");
        assertTrue(md.contains("www.example.com:443"), "unowned row listed under ownership gaps");
        String json = Files.readString(w.json());
        assertTrue(json.contains("\"why\""));
        assertTrue(json.contains("\"2026-09-25T12:00:00Z\""), "instants as ISO-8601");
        assertFalse(json.contains("\"chain\""), "certificates live only in the certificate table");
        assertTrue(Files.readString(w.coverageCsv()).contains("<title>502 Bad Gateway</title>"), "CSV keeps the body as received");
        assertTrue(md.contains("&lt;title&gt;502 Bad Gateway&lt;/title&gt;"), "report escapes it so it does not render");
    }

    @Test
    @DisplayName("Findings CSV quotes every field and neutralises spreadsheet formulas")
    void csvSafety() {
        String csv = AuditReportWriter.findingsCsv(sample());
        String row = csv.lines().skip(1).findFirst().orElseThrow();
        assertTrue(row.contains("\"'=HYPERLINK(\"\"http://evil\"\") issue \"\"ca, inc\"\" has no validationmethods\""), row);
    }

    @Test
    @DisplayName("A written JSON export loads back as a --baseline with its observations and certificate subjects")
    void baselineRoundTrip(@TempDir Path dir) throws Exception {
        AuditReportWriter.Written w = AuditReportWriter.write(sample(), dir);
        BaselineLoader.Baseline b = BaselineLoader.load(w.json());
        BaselineObservation o = b.observations().get(0);
        assertEquals("www.example.com", o.host());
        assertEquals(443, o.port());
        assertEquals(CertFingerprints.sha256(C.leaf()), o.leafSha256());
        assertEquals(2, o.chainSha256().size());
        assertEquals(NOW, o.observedAt());
        assertEquals(C.inter().getSubjectX500Principal().getName(), b.subjectBySha().get(CertFingerprints.sha256(C.inter())));
    }

    @Test
    @DisplayName("Every finding type the analysers can emit has catalogue text")
    void catalogueComplete() {
        for (String t : List.of("NODE_DIVERGENCE", "CHAIN_CHANGED", "EXPIRED_SERVED_CERT", "EXPIRED_IN_CHAIN", "ROOT_INCLUDED",
                "WRONG_ORDER", "MISSING_INTERMEDIATE", "AIA_ONLY_COMPLETION", "WEAK_SIGNATURE", "WEAK_KEY",
                "UNOBSERVED_ISSUANCE", "CT_FINGERPRINT_MISMATCH", "CAA_ABSENT", "CAA_NO_ACCOUNT_BINDING",
                "CAA_NO_METHOD_BINDING", "CAA_WILDCARD_UNRESTRICTED")) {
            assertTrue(FindingCatalog.isKnown(t), t);
        }
    }
}
