package com.codecatalyst.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class AuditOptionsTest {

    @Test
    @DisplayName("Requester and basis are mandatory, so every run records who asked and why")
    void requesterAndBasisRequired() {
        assertThrows(IllegalArgumentException.class, () -> AuditOptions.parse(new String[]{"-audit", "--csv", "t.csv", "--basis", "OWN"}, 1));
        assertThrows(IllegalArgumentException.class, () -> AuditOptions.parse(new String[]{"-audit", "--csv", "t.csv", "--requester", "Suman"}, 1));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> AuditOptions.parse(new String[]{"-audit", "--csv", "t.csv", "--requester", "S", "--basis", "whatever"}, 1));
        assertTrue(e.getMessage().contains("OWN, CONSENT or PUBLIC_PROSPECT"));
    }

    @Test
    @DisplayName("Defaults: out '.', resolver 8.8.8.8, concurrency 4, CT cache 6 h, DER matching off")
    void defaults() {
        AuditOptions o = AuditOptions.parse(new String[]{"-audit", "--csv", "t.csv", "--requester", "S", "--basis", "consent"}, 1);
        assertEquals(Path.of("t.csv"), o.csv());
        assertEquals(Path.of("."), o.outDir());
        assertEquals("8.8.8.8", o.resolver());
        assertEquals(4, o.concurrency());
        assertEquals(6, o.ctCacheTtlHours());
        assertFalse(o.ctFetchDer());
        assertEquals(AuditOptions.Basis.CONSENT, o.basis());
        assertEquals(java.util.List.of("crtsh", "certspotter"), o.ctSources());
    }

    @Test
    @DisplayName("Unknown flags and out-of-range numbers are rejected")
    void rejectsBadInput() {
        assertThrows(IllegalArgumentException.class, () -> AuditOptions.parse(new String[]{"-audit", "--port", "443"}, 1));
        assertThrows(IllegalArgumentException.class, () -> AuditOptions.parse(new String[]{"-audit", "--csv", "t", "--requester", "S",
                "--basis", "OWN", "--concurrency", "0"}, 1));
        assertThrows(IllegalArgumentException.class, () -> AuditOptions.parse(new String[]{"-audit", "--csv"}, 1));
    }

    @Test
    @DisplayName("--ct-sources picks sources in fixed order and rejects unknown names")
    void ctSources() {
        AuditOptions o = AuditOptions.parse(new String[]{"-audit", "--csv", "t", "--requester", "S", "--basis", "OWN",
                "--ct-sources", "certspotter, CRTSH"}, 1);
        assertEquals(java.util.List.of("crtsh", "certspotter"), o.ctSources());
        assertEquals(java.util.List.of("certspotter"), AuditOptions.parse(new String[]{"-audit", "--csv", "t", "--requester", "S",
                "--basis", "OWN", "--ct-sources", "certspotter"}, 1).ctSources());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> AuditOptions.parse(new String[]{"-audit",
                "--csv", "t", "--requester", "S", "--basis", "OWN", "--ct-sources", "censys"}, 1));
        assertTrue(e.getMessage().contains("censys"));
    }
}
