package com.codecatalyst.audit.caa;

import com.codecatalyst.audit.TestCerts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CaaResolverTest {

    private static final Clock CLOCK = Clock.fixed(TestCerts.NOW, ZoneOffset.UTC);
    private static final CaaAnswer EMPTY = new CaaAnswer(0, "NOERROR", true, List.of());
    private static final CaaAnswer NX = new CaaAnswer(3, "NXDOMAIN", true, List.of());

    static final class Fake implements CaaQuerier {
        final Map<String, CaaAnswer> answers;
        final List<String> asked = new ArrayList<>();
        Fake(Map<String, CaaAnswer> answers) { this.answers = answers; }
        @Override public CaaAnswer query(String name) {
            asked.add(name);
            return answers.getOrDefault(name, EMPTY);
        }
    }

    @Test
    @DisplayName("A name with no CAA of its own reports the parent's record and the owner name it was found at")
    void inheritsFromParent() throws Exception {
        CaaProperty issue = new CaaProperty(0, "issue", "letsencrypt.org");
        Fake dns = new Fake(Map.of("example.com", new CaaAnswer(0, "NOERROR", true, List.of(issue))));
        CaaResolution r = new CaaResolver(dns, "8.8.8.8", CLOCK).resolve("www.example.com");
        assertEquals("example.com", r.foundAtName());
        assertEquals("www.example.com", r.queriedName());
        assertEquals(List.of(issue), r.records());
        assertEquals("8.8.8.8", r.resolver());
        assertEquals("VALIDATED_BY_RESOLVER", r.dnssecStatus());
        assertEquals(List.of("www.example.com", "example.com"), dns.asked);
    }

    @Test
    @DisplayName("The climb follows RFC 8659 to the TLD, past a multi-label public suffix, with no 2-label floor")
    void climbsToTld() throws Exception {
        Fake dns = new Fake(Map.of("a.example.co.uk", NX));
        CaaResolution r = new CaaResolver(dns, "8.8.8.8", CLOCK).resolve("a.example.co.uk");
        assertEquals(List.of("a.example.co.uk", "example.co.uk", "co.uk", "uk"), dns.asked);
        assertNull(r.foundAtName());
        assertTrue(r.records().isEmpty());
    }

    @Test
    @DisplayName("SERVFAIL stops the climb with the rcode as received: an unknown answer is never 'no CAA'")
    void servfailIsAnError() {
        Fake dns = new Fake(Map.of("example.com", new CaaAnswer(2, "SERVFAIL", false, List.of())));
        CaaLookupException e = assertThrows(CaaLookupException.class,
                () -> new CaaResolver(dns, "8.8.8.8", CLOCK).resolve("www.example.com"));
        assertEquals("CAA query for example.com via 8.8.8.8 returned SERVFAIL", e.getMessage());
    }

    @Test
    @DisplayName("A transport failure is reported with its exception type and message")
    void timeoutIsAnError() {
        CaaQuerier dns = name -> { throw new SocketTimeoutException("Timed out while trying to resolve"); };
        CaaLookupException e = assertThrows(CaaLookupException.class,
                () -> new CaaResolver(dns, "9.9.9.9", CLOCK).resolve("example.com"));
        assertEquals("CAA query for example.com via 9.9.9.9 failed: SocketTimeoutException: Timed out while trying to resolve",
                e.getMessage());
    }

    @Test
    @DisplayName("Absence is only reported validated when every negative answer in the climb carried AD")
    void absenceValidation() throws Exception {
        Fake dns = new Fake(Map.of("com", new CaaAnswer(0, "NOERROR", false, List.of())));
        assertEquals("UNVALIDATED", new CaaResolver(dns, "8.8.8.8", CLOCK).resolve("example.com").dnssecStatus());
    }

    @Test
    @DisplayName("A trailing dot on the queried name is ignored")
    void trailingDot() throws Exception {
        Fake dns = new Fake(Map.of());
        new CaaResolver(dns, "8.8.8.8", CLOCK).resolve("example.com.");
        assertEquals(List.of("example.com", "com"), dns.asked);
    }
}
