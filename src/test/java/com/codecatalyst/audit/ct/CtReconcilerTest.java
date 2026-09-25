package com.codecatalyst.audit.ct;

import com.codecatalyst.audit.Finding;
import com.codecatalyst.audit.TestCerts;
import com.codecatalyst.audit.served.CertFingerprints;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static com.codecatalyst.audit.TestCerts.*;
import static org.junit.jupiter.api.Assertions.*;

class CtReconcilerTest {

    private static final TestCerts.Chain C = TestCerts.chain();
    // crt.sh renders issuers in the reverse order with ", " separators
    private static final String CRTSH_ISSUER = "C=GB, O=Test, CN=Test Intermediate";

    static CtEntry entry(long id, String issuer, String serialHex, Instant nb, Instant na) {
        return new CtEntry(id, issuer, serialHex, "www.example.com", List.of("www.example.com"), nb, na, nb.plusSeconds(id));
    }

    static CtEntry valid(long id, String serialHex) {
        return entry(id, CRTSH_ISSUER, serialHex, NOW.minus(Duration.ofDays(10)), NOW.plus(Duration.ofDays(80)));
    }

    static CtReconciler.ServedLeaf served(X509Certificate c) {
        return new CtReconciler.ServedLeaf(c, CertFingerprints.sha256(c), "observation www.example.com:443@192.0.2.1");
    }

    @Test
    @DisplayName("A precertificate and its final certificate (same issuer and serial) reconcile to one issuance")
    void precertAndFinalAreOne() {
        List<CtIssuance> r = CtReconciler.reconcile(List.of(valid(10, "0abc"), valid(11, "0ABC")));
        assertEquals(1, r.size());
        assertEquals(List.of(10L, 11L), r.get(0).crtShIds());
    }

    @Test
    @DisplayName("Same serial from two different issuers is two issuances")
    void sameSerialDifferentIssuer() {
        CtEntry other = entry(12, "C=US, O=Other CA, CN=X1", "0abc", NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(1)));
        assertEquals(2, CtReconciler.reconcile(List.of(valid(10, "0abc"), other)).size());
    }

    @Test
    @DisplayName("A currently valid issuance that no audited endpoint serves raises UNOBSERVED_ISSUANCE with its crt.sh reference")
    void unobserved() throws Exception {
        List<CtIssuance> iss = CtReconciler.reconcile(List.of(valid(10, "0f0f")));
        CtReconciler.Outcome o = CtReconciler.detectUnobserved("example.com", iss, List.of(served(C.leaf())), NOW, NOW, null);
        assertEquals(1, o.findings().size());
        Finding f = o.findings().get(0);
        assertEquals("UNOBSERVED_ISSUANCE", f.type());
        assertTrue(f.evidence().contains("https://crt.sh/?id=10"));
        assertTrue(f.detail().contains("www.example.com"));
        assertEquals(1, o.currentlyValid());
        assertEquals(0, o.matched());
    }

    @Test
    @DisplayName("Expired issuances are history: they never raise UNOBSERVED_ISSUANCE")
    void expiredIsHistory() throws Exception {
        CtEntry old = entry(9, CRTSH_ISSUER, "0e0e", NOW.minus(Duration.ofDays(200)), NOW.minus(Duration.ofDays(110)));
        CtReconciler.Outcome o = CtReconciler.detectUnobserved("example.com", CtReconciler.reconcile(List.of(old)),
                List.of(), NOW, NOW, null);
        assertTrue(o.findings().isEmpty());
        assertEquals(0, o.currentlyValid());
    }

    @Test
    @DisplayName("A served leaf matches its CT entry on serial and issuer despite crt.sh's different DN rendering")
    void servedMatches() throws Exception {
        String serial = C.leaf().getSerialNumber().toString(16);
        CtReconciler.Outcome o = CtReconciler.detectUnobserved("example.com",
                CtReconciler.reconcile(List.of(valid(10, serial))), List.of(served(C.leaf())), NOW, NOW, null);
        assertTrue(o.findings().isEmpty());
        assertEquals(1, o.matched());
    }

    @Test
    @DisplayName("Matching serial from a different issuer is still unobserved")
    void serialAloneIsNotAMatch() throws Exception {
        String serial = C.leaf().getSerialNumber().toString(16);
        CtEntry e = entry(10, "C=US, O=Other CA, CN=X1", serial, NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(1)));
        CtReconciler.Outcome o = CtReconciler.detectUnobserved("example.com", CtReconciler.reconcile(List.of(e)),
                List.of(served(C.leaf())), NOW, NOW, null);
        assertEquals(List.of("UNOBSERVED_ISSUANCE"), o.findings().stream().map(Finding::type).toList());
    }

    static byte[] der(X509Certificate c) {
        try {
            return c.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    @DisplayName("With --ct-fetch-der, a final CT certificate whose SHA-256 differs from the served one raises CT_FINGERPRINT_MISMATCH")
    void fingerprintMismatch() throws Exception {
        X509Certificate imposter = cert("www.example.com").issuedBy(C.inter(), INTER_KEY)
                .serial(C.leaf().getSerialNumber()).validity(NOW.minus(Duration.ofDays(2)), NOW.plus(Duration.ofDays(9))).build();
        String serial = C.leaf().getSerialNumber().toString(16);
        CtReconciler.Outcome o = CtReconciler.detectUnobserved("example.com",
                CtReconciler.reconcile(List.of(valid(10, serial))), List.of(served(C.leaf())), NOW, NOW,
                id -> der(imposter));
        assertEquals(List.of("CT_FINGERPRINT_MISMATCH"), o.findings().stream().map(Finding::type).toList());
    }

    @Test
    @DisplayName("With --ct-fetch-der, a matching final certificate confirms the match silently")
    void fingerprintMatch() throws Exception {
        String serial = C.leaf().getSerialNumber().toString(16);
        CtReconciler.Outcome o = CtReconciler.detectUnobserved("example.com",
                CtReconciler.reconcile(List.of(valid(10, serial))), List.of(served(C.leaf())), NOW, NOW,
                id -> der(C.leaf()));
        assertTrue(o.findings().isEmpty());
        assertTrue(o.derErrors().isEmpty());
    }

    @Test
    @DisplayName("A DER fetch failure is reported as a DER error, not as a mismatch")
    void derFetchFailure() throws Exception {
        String serial = C.leaf().getSerialNumber().toString(16);
        CtReconciler.Outcome o = CtReconciler.detectUnobserved("example.com",
                CtReconciler.reconcile(List.of(valid(10, serial))), List.of(served(C.leaf())), NOW, NOW,
                id -> { throw new CtLookupException("crt.sh HTTP 502 for https://crt.sh/?d=10 (attempt 2 of 2): x"); });
        assertTrue(o.findings().isEmpty());
        assertEquals(List.of("crt.sh HTTP 502 for https://crt.sh/?d=10 (attempt 2 of 2): x"), o.derErrors());
    }

    @Test
    @DisplayName("Serial numbers compare as integers: leading zeros and case do not matter")
    void serialNormalisation() throws Exception {
        String serial = "00" + C.leaf().getSerialNumber().toString(16).toUpperCase();
        CtReconciler.Outcome o = CtReconciler.detectUnobserved("example.com",
                CtReconciler.reconcile(List.of(valid(10, serial))), List.of(served(C.leaf())), NOW, NOW, null);
        assertEquals(1, o.matched());
        assertEquals(C.leaf().getSerialNumber(), new BigInteger(serial, 16));
    }
}
