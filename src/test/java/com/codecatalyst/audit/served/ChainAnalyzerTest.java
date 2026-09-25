package com.codecatalyst.audit.served;

import com.codecatalyst.audit.Finding;
import com.codecatalyst.audit.Severity;
import com.codecatalyst.audit.TestCerts;
import com.codecatalyst.audit.TestCerts.Chain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

import static com.codecatalyst.audit.TestCerts.*;
import static org.junit.jupiter.api.Assertions.*;

class ChainAnalyzerTest {

    private static final Chain C = TestCerts.chain();
    private static final TrustAnchors ANCHORS = new TrustAnchors(List.of(C.root()), "test");

    static AddressObservation obs(String address, X509Certificate... chain) {
        List<String> fps = Arrays.stream(chain).map(CertFingerprints::sha256).toList();
        return new AddressObservation("www.example.com", 443, address, true, fps, fps.get(0),
                CertFingerprints.chainHash(fps), "TLSv1.3", "TLS_AES_128_GCM_SHA256", null, NOW, chain);
    }

    private static List<String> types(List<Finding> fs) {
        return fs.stream().map(Finding::type).sorted().toList();
    }

    private static List<Finding> defects(X509Certificate... chain) {
        return ChainAnalyzer.detectChainDefects("example.com", obs("192.0.2.1", chain), ANCHORS, NOW);
    }

    @Test
    @DisplayName("A correctly served leaf + intermediate chain (root omitted) produces no findings")
    void correctChainIsClean() {
        assertEquals(List.of(), types(defects(C.leaf(), C.inter())));
    }

    @Test
    @DisplayName("A chain that continues past a trust anchor into a cross-sign from an unknown root is clean (example.com, 2026-09-25)")
    void stopsAtFirstAnchor() {
        X509Certificate oldRoot = cert("Legacy Root").keys(INTER2_KEY).ca().selfSigned().build();
        X509Certificate crossSign = cert("Test Root").keys(ROOT_KEY).ca().issuedBy(oldRoot, INTER2_KEY).build();
        assertEquals(List.of(), types(defects(C.leaf(), C.inter(), crossSign)));
    }

    @Test
    @DisplayName("A leaf served alone with no AIA raises exactly MISSING_INTERMEDIATE")
    void missingIntermediateWithoutAia() {
        assertEquals(List.of("MISSING_INTERMEDIATE"), types(defects(C.leaf())));
    }

    @Test
    @DisplayName("A leaf served alone with an AIA issuer URL raises exactly AIA_ONLY_COMPLETION, naming the URL")
    void aiaOnlyCompletion() {
        X509Certificate leaf = cert("www.example.com").issuedBy(C.inter(), INTER_KEY).aia("http://ca.test/inter.der").build();
        List<Finding> fs = defects(leaf);
        assertEquals(List.of("AIA_ONLY_COMPLETION"), types(fs));
        assertTrue(fs.get(0).detail().contains("http://ca.test/inter.der"));
    }

    @Test
    @DisplayName("A chain that includes its root raises exactly ROOT_INCLUDED")
    void rootIncluded() {
        assertEquals(List.of("ROOT_INCLUDED"), types(defects(C.leaf(), C.inter(), C.root())));
    }

    @Test
    @DisplayName("Intermediates sent out of order raise exactly WRONG_ORDER")
    void wrongOrder() {
        X509Certificate inter2 = cert("Test Intermediate 2").keys(INTER2_KEY).ca().issuedBy(C.inter(), INTER_KEY).build();
        X509Certificate leaf = cert("www.example.com").issuedBy(inter2, INTER2_KEY).build();
        assertEquals(List.of(), types(defects(leaf, inter2, C.inter())), "in order is clean");
        assertEquals(List.of("WRONG_ORDER"), types(defects(leaf, C.inter(), inter2)));
    }

    @Test
    @DisplayName("An expired leaf is EXPIRED_SERVED_CERT at CRITICAL")
    void expiredLeafIsCritical() {
        X509Certificate leaf = cert("www.example.com").issuedBy(C.inter(), INTER_KEY).expired().build();
        List<Finding> fs = defects(leaf, C.inter());
        assertEquals(List.of("EXPIRED_SERVED_CERT"), types(fs));
        assertEquals(Severity.CRITICAL, fs.get(0).severity());
    }

    @Test
    @DisplayName("An expired certificate further up the chain is EXPIRED_IN_CHAIN at MEDIUM, not CRITICAL")
    void expiredIntermediateIsMedium() {
        X509Certificate inter = cert("Test Intermediate").keys(INTER_KEY).ca().issuedBy(C.root(), ROOT_KEY).expired().build();
        List<Finding> fs = defects(C.leaf(), inter);
        assertEquals(List.of("EXPIRED_IN_CHAIN"), types(fs));
        assertEquals(Severity.MEDIUM, fs.get(0).severity());
    }

    @Test
    @DisplayName("A SHA-1 signed intermediate raises WEAK_SIGNATURE")
    void weakSignatureOnIntermediate() {
        X509Certificate inter = cert("Test Intermediate").keys(INTER_KEY).ca().issuedBy(C.root(), ROOT_KEY).sigAlg("SHA1withRSA").build();
        assertEquals(List.of("WEAK_SIGNATURE"), types(defects(C.leaf(), inter)));
    }

    @Test
    @DisplayName("A SHA-1 self-signed root is not WEAK_SIGNATURE: nobody verifies a root's own signature")
    void weakSignatureIgnoresSelfSignedRoot() {
        X509Certificate root = cert("Test Root").keys(ROOT_KEY).ca().selfSigned().sigAlg("SHA1withRSA").build();
        assertEquals(List.of("ROOT_INCLUDED"), types(defects(C.leaf(), C.inter(), root)));
    }

    @Test
    @DisplayName("A 1024-bit RSA leaf key raises WEAK_KEY")
    void weakKey() {
        X509Certificate leaf = cert("www.example.com").keys(WEAK_KEY).issuedBy(C.inter(), INTER_KEY).build();
        assertEquals(List.of("WEAK_KEY"), types(defects(leaf, C.inter())));
    }

    @Test
    @DisplayName("An unreachable observation yields no chain findings")
    void unreachableHasNoDefects() {
        AddressObservation down = new AddressObservation("h", 443, "192.0.2.9", false, List.of(), null, null,
                null, null, "refused", NOW, null);
        assertTrue(ChainAnalyzer.detectChainDefects("h", down, ANCHORS, NOW).isEmpty());
    }

    @Test
    @DisplayName("Two addresses serving different leaves raise NODE_DIVERGENCE naming both addresses")
    void nodeDivergence() {
        X509Certificate stale = cert("www.example.com").issuedBy(C.inter(), INTER_KEY).build();
        Optional<Finding> f = ChainAnalyzer.detectNodeDivergence("example.com",
                List.of(obs("192.0.2.1", C.leaf(), C.inter()), obs("192.0.2.2", stale, C.inter())));
        assertTrue(f.isPresent());
        assertEquals(Severity.HIGH, f.get().severity());
        assertTrue(f.get().detail().contains("192.0.2.1") && f.get().detail().contains("192.0.2.2"));
    }

    @Test
    @DisplayName("Identical nodes, and unreachable nodes, do not raise NODE_DIVERGENCE")
    void noDivergence() {
        AddressObservation down = new AddressObservation("www.example.com", 443, "192.0.2.3", false, List.of(),
                null, null, null, null, "timeout", NOW, null);
        assertTrue(ChainAnalyzer.detectNodeDivergence("example.com", List.of(obs("192.0.2.1", C.leaf(), C.inter()),
                obs("192.0.2.2", C.leaf(), C.inter()), down)).isEmpty());
    }

    @Test
    @DisplayName("Same leaf with a different chain than the baseline raises CHAIN_CHANGED listing removed and added certs")
    void chainChanged() {
        X509Certificate otherInter = cert("Other Intermediate").keys(INTER_KEY).ca().issuedBy(C.root(), ROOT_KEY).build();
        AddressObservation now = obs("192.0.2.1", C.leaf(), otherInter);
        AddressObservation before = obs("192.0.2.7", C.leaf(), C.inter());
        BaselineObservation b = new BaselineObservation("www.example.com", 443, "192.0.2.7", before.leafSha256(),
                before.chainHash(), before.chainSha256(), Instant.parse("2026-09-01T00:00:00Z"));
        Map<String, String> subjects = Map.of(
                CertFingerprints.sha256(C.inter()), "CN=Test Intermediate",
                CertFingerprints.sha256(otherInter), "CN=Other Intermediate");
        Optional<Finding> f = ChainAnalyzer.detectChainChanged("example.com", now, List.of(b), subjects);
        assertTrue(f.isPresent());
        assertEquals(Severity.HIGH, f.get().severity());
        assertTrue(f.get().detail().contains("removed: CN=Test Intermediate"), f.get().detail());
        assertTrue(f.get().detail().contains("added: CN=Other Intermediate"), f.get().detail());
    }

    @Test
    @DisplayName("CHAIN_CHANGED is not raised when any same-leaf baseline observation had this chain")
    void chainUnchangedOnAnyMatch() {
        AddressObservation now = obs("192.0.2.1", C.leaf(), C.inter());
        BaselineObservation same = new BaselineObservation("www.example.com", 443, "192.0.2.99", now.leafSha256(),
                now.chainHash(), now.chainSha256(), NOW);
        BaselineObservation other = new BaselineObservation("www.example.com", 443, "192.0.2.98", now.leafSha256(),
                "00", List.of(), NOW);
        assertTrue(ChainAnalyzer.detectChainChanged("example.com", now, List.of(other, same), Map.of()).isEmpty());
    }

    @Test
    @DisplayName("caIssuersUrl reads the AIA caIssuers URI and is empty without AIA")
    void aiaParsing() {
        X509Certificate withAia = cert("x").issuedBy(C.inter(), INTER_KEY).aia("http://r11.i.lencr.org/").build();
        assertEquals(Optional.of("http://r11.i.lencr.org/"), ChainAnalyzer.caIssuersUrl(withAia));
        assertEquals(Optional.empty(), ChainAnalyzer.caIssuersUrl(C.leaf()));
    }

    @Test
    @DisplayName("TrustAnchors only accepts a certificate the anchor actually signed, not one with a matching DN")
    void anchorsCheckSignature() {
        assertTrue(ANCHORS.signs(C.inter()));
        X509Certificate forged = cert("Test Intermediate").keys(INTER_KEY).ca().issuedBy(C.root(), INTER2_KEY).build();
        assertFalse(ANCHORS.signs(forged));
    }
}
