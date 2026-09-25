package com.codecatalyst.audit.caa;

import com.codecatalyst.audit.Finding;
import com.codecatalyst.audit.Severity;
import com.codecatalyst.audit.TestCerts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CaaEvaluatorTest {

    static CaaResolution res(CaaProperty... props) {
        return new CaaResolution("example.com", props.length == 0 ? null : "example.com", List.of(props), "8.8.8.8",
                "UNVALIDATED", TestCerts.NOW);
    }

    static List<String> types(List<Finding> fs) {
        return fs.stream().map(Finding::type).sorted().toList();
    }

    @Test
    @DisplayName("F1's pre-fix record (issue \"letsencrypt.org\", no parameters) raises NO_ACCOUNT_BINDING and NO_METHOD_BINDING")
    void f1Record() {
        List<Finding> fs = CaaEvaluator.evaluate("example.com", res(new CaaProperty(0, "issue", "letsencrypt.org")));
        assertEquals(List.of("CAA_NO_ACCOUNT_BINDING", "CAA_NO_METHOD_BINDING", "CAA_WILDCARD_UNRESTRICTED"), types(fs));
        Finding acct = fs.stream().filter(f -> f.type().equals("CAA_NO_ACCOUNT_BINDING")).findFirst().orElseThrow();
        assertEquals(Severity.MEDIUM, acct.severity());
        assertTrue(acct.remediation().contains("March 2027"));
    }

    @Test
    @DisplayName("issue \";\" forbids issuance and raises nothing, even without issuewild")
    void forbidAllIsNotAGap() {
        assertEquals(List.of(), types(CaaEvaluator.evaluate("example.com", res(new CaaProperty(0, "issue", ";")))));
    }

    @Test
    @DisplayName("A fully bound record with an explicit issuewild raises nothing")
    void fullyBound() {
        String v = "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1; validationmethods=http-01";
        assertEquals(List.of(), types(CaaEvaluator.evaluate("example.com",
                res(new CaaProperty(0, "issue", v), new CaaProperty(0, "issuewild", ";")))));
    }

    @Test
    @DisplayName("No CAA anywhere raises CAA_ABSENT at LOW")
    void absent() {
        List<Finding> fs = CaaEvaluator.evaluate("example.com", res());
        assertEquals(List.of("CAA_ABSENT"), types(fs));
        assertEquals(Severity.LOW, fs.get(0).severity());
    }

    @Test
    @DisplayName("Parameters are parsed after the CA domain, keys case-insensitively")
    void parameters() {
        CaaProperty p = new CaaProperty(128, "issue", "ca.example; AccountURI=https://x ; validationmethods=dns-01");
        assertEquals("ca.example", p.issuerDomain());
        assertEquals(Map.of("accounturi", "https://x", "validationmethods", "dns-01"), p.parameters());
        assertTrue(p.critical());
    }
}
