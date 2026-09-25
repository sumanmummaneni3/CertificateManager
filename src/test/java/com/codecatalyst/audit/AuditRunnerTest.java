package com.codecatalyst.audit;

import com.codecatalyst.audit.caa.CaaAnswer;
import com.codecatalyst.audit.caa.CaaProperty;
import com.codecatalyst.audit.caa.CaaResolver;
import com.codecatalyst.audit.ct.*;
import com.codecatalyst.audit.served.*;
import com.codecatalyst.net.FetchCertificates.ServedHandshake;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static com.codecatalyst.audit.TestCerts.*;
import static org.junit.jupiter.api.Assertions.*;

class AuditRunnerTest {

    private static final Chain C = TestCerts.chain();
    private static final X509Certificate API_LEAF = cert("api.example.com").issuedBy(C.inter(), INTER_KEY).build();
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final AuditReport.RunMeta META = new AuditReport.RunMeta("CertificateManager", "test", null, null,
            "tester", "OWN", "t.csv", null, "8.8.8.8", null, 0, false);

    static AuditTarget target(String host, String domain) {
        return new AuditTarget(host, 443, domain, "", Map.of(), 2);
    }

    static CtEntry ctFor(long id, X509Certificate c) {
        return new CtEntry(id, "C=GB, O=Test, CN=Test Intermediate", c.getSerialNumber().toString(16),
                "x", List.of("x"), NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(60)), NOW.minus(Duration.ofDays(1)));
    }

    /** A CT source that answers from a fixed list, or fails with a fixed message. */
    static CtLogSource ct(List<CtEntry> entries, String failure) {
        return new CtLogSource() {
            @Override public CtFetchResult fetch(String domain) throws CtLookupException {
                if (failure != null) throw new CtLookupException(failure);
                return new CtFetchResult(entries, NOW, false, List.of("https://crt.sh/?q=" + domain));
            }
            @Override public byte[] fetchDer(long id) { throw new AssertionError("DER not requested"); }
        };
    }

    static AuditRunner runner(CtLogSource ct) {
        ServedStateProber prober = new ServedStateProber(host -> {
            if (host.startsWith("gone")) throw new UnknownHostException(host + ": Name or service not known");
            return new InetAddress[]{InetAddress.getByName("192.0.2.1")};
        }, (addr, host, port) -> new ServedHandshake(new X509Certificate[]{host.startsWith("api") ? API_LEAF : C.leaf(), C.inter()},
                "TLSv1.3", "TLS_AES_128_GCM_SHA256"), 2, CLOCK);
        CaaResolver caa = new CaaResolver(name -> name.equals("example.com")
                ? new CaaAnswer(0, "NOERROR", false, List.of(new CaaProperty(0, "issue", "letsencrypt.org")))
                : new CaaAnswer(0, "NOERROR", false, List.of()), "8.8.8.8", CLOCK);
        return new AuditRunner(prober, caa, ct, new TrustAnchors(List.of(C.root()), "test"), CLOCK, 2, false);
    }

    static List<CheckStatus> coverage(AuditReport r, String check) {
        return r.coverage().stream().filter(c -> c.check().equals(check)).toList();
    }

    @Test
    @DisplayName("CT for a domain is pulled once and checked against every host in the run, so a sibling host's cert is not 'unobserved'")
    void ctGroupedByDomain() throws Exception {
        int[] calls = {0};
        CtLogSource source = new CtLogSource() {
            @Override public CtFetchResult fetch(String d) {
                calls[0]++;
                return new CtFetchResult(List.of(ctFor(1, C.leaf()), ctFor(2, API_LEAF)), NOW, false, List.of());
            }
            @Override public byte[] fetchDer(long id) { throw new AssertionError(); }
        };
        AuditReport r = runner(source).run(List.of(target("www.example.com", "example.com"), target("api.example.com", "example.com")),
                List.of(), null, META);
        assertEquals(1, calls[0]);
        assertTrue(r.findings().stream().noneMatch(f -> f.type().equals("UNOBSERVED_ISSUANCE")), r.findings().toString());
        assertEquals(1, r.ct().size());
        assertEquals(2, r.ct().get(0).matched());
    }

    @Test
    @DisplayName("A certificate in CT that no audited host serves is UNOBSERVED_ISSUANCE")
    void unobservedAcrossRun() throws Exception {
        X509Certificate stray = cert("shadow.example.com").issuedBy(C.inter(), INTER_KEY).build();
        AuditReport r = runner(ct(List.of(ctFor(1, C.leaf()), ctFor(9, stray)), null))
                .run(List.of(target("www.example.com", "example.com")), List.of(), null, META);
        assertEquals(1, r.findings().stream().filter(f -> f.type().equals("UNOBSERVED_ISSUANCE")).count());
    }

    @Test
    @DisplayName("A crt.sh failure is recorded as a CT ERROR with the message as received, and CT-03 as NOT_CHECKED, never as clean")
    void ctFailureIsCoverageNotSilence() throws Exception {
        String msg = "crt.sh HTTP 502 for https://crt.sh/?q=example.com&output=json (attempt 2 of 2): <html>502 Bad Gateway</html>";
        AuditReport r = runner(ct(List.of(), msg)).run(List.of(target("www.example.com", "example.com")), List.of(), null, META);
        assertEquals(List.of(CheckStatus.error("example.com", "ct", msg)), coverage(r, "ct"));
        assertEquals(CheckStatus.Status.NOT_CHECKED, coverage(r, "ct03").get(0).status());
        assertTrue(r.ct().isEmpty());
        assertTrue(coverage(r, "caa").stream().allMatch(c -> c.status() == CheckStatus.Status.OK), "other checks still ran");
    }

    @Test
    @DisplayName("A host that does not resolve is a VER ERROR, and CT-03 for its domain is NOT_CHECKED rather than flagging everything")
    void unresolvableHost() throws Exception {
        AuditReport r = runner(ct(List.of(ctFor(1, C.leaf())), null))
                .run(List.of(target("gone.example.com", "example.com")), List.of(), null, META);
        CheckStatus ver = coverage(r, "ver").get(0);
        assertEquals(CheckStatus.Status.ERROR, ver.status());
        assertTrue(ver.message().startsWith("DNS resolution failed: gone.example.com"));
        assertEquals(CheckStatus.Status.NOT_CHECKED, coverage(r, "ct03").get(0).status());
        assertTrue(r.findings().stream().noneMatch(f -> f.type().equals("UNOBSERVED_ISSUANCE")));
    }

    @Test
    @DisplayName("Without --baseline, chain change is NOT_CHECKED for every host:port")
    void noBaseline() throws Exception {
        AuditReport r = runner(ct(List.of(), null)).run(List.of(target("www.example.com", null)), List.of(), null, META);
        assertEquals(List.of(CheckStatus.notChecked("www.example.com:443", "chn02", "no --baseline given")), coverage(r, "chn02"));
    }

    @Test
    @DisplayName("Findings carry evidence, time, why and remediation; the certificate table holds each cert once")
    void findingShapeAndCertTable() throws Exception {
        AuditReport r = runner(ct(List.of(), null)).run(List.of(target("www.example.com", "example.com"),
                target("api.example.com", "example.com")), List.of(), null, META);
        assertEquals(3, r.certificates().size(), "two leaves and one shared intermediate");
        Finding caa = r.findings().stream().filter(f -> f.type().equals("CAA_NO_ACCOUNT_BINDING")).findFirst().orElseThrow();
        assertTrue(caa.evidence().contains("found at example.com via 8.8.8.8"));
        assertEquals(NOW, caa.observedAt());
        assertFalse(caa.why().isBlank());
        assertFalse(caa.remediation().isBlank());
        assertEquals("tester", r.meta().requester());
        assertEquals(NOW, r.meta().startedAt());
    }
}
