package com.codecatalyst.audit.ct;

import com.codecatalyst.audit.TestCerts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class CertSpotterSourceTest {

    private static final Clock CLOCK = Clock.fixed(TestCerts.NOW, ZoneOffset.UTC);

    /** A real Cert Spotter answer for example.com, recorded 2026-09-25 (3 of its 9 issuances). */
    static String realPage() {
        try (InputStream in = CertSpotterSourceTest.class.getResourceAsStream("/ct/certspotter-example.com-2026-09-25.json")) {
            return new String(Objects.requireNonNull(in).readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static final class FakeHttp implements HttpFetcher {
        final Deque<Object> answers = new ArrayDeque<>();
        final List<String> urls = new ArrayList<>();
        final List<Map<String, String>> headers = new ArrayList<>();

        FakeHttp then(int status, String body) { return then(status, body, Map.of()); }
        FakeHttp then(int status, String body, Map<String, List<String>> h) {
            answers.add(new Response(status, body.getBytes(StandardCharsets.UTF_8), h));
            return this;
        }

        @Override
        public Response get(URI uri, Map<String, String> requestHeaders) throws IOException {
            urls.add(uri.toString());
            headers.add(requestHeaders);
            Object a = answers.poll();
            if (a == null) throw new AssertionError("unexpected request " + uri);
            if (a instanceof IOException e) throw e;
            return (Response) a;
        }
    }

    private CertSpotterSource source(FakeHttp http, Path dir, String key) {
        return new CertSpotterSource(http, new RateGate(0), new CtCache(dir, Duration.ZERO, CLOCK), CLOCK, key);
    }

    @Test
    @DisplayName("A real recorded response parses: serial and issuer come from cert_der, SHA-256 is checked, final certs are marked")
    void parsesRealResponse() throws Exception {
        List<CtEntry> es = CertSpotterSource.parse("u", realPage());
        assertEquals(3, es.size());
        CtEntry served = es.stream().filter(e -> e.entryId().equals("16164256171")).findFirst().orElseThrow();
        assertEquals("624d0ab311558780b7d5213b9631831", served.serialHex());
        assertTrue(served.issuerName().contains("CN=Cloudflare TLS Issuing"), served.issuerName());
        assertEquals("6153a96fd1a6ab7f4d438fc34932484299d0729d9140b3a126bb2f9c07b02200", served.certSha256());
        assertEquals(Boolean.FALSE, served.precert());
        assertNull(served.entryTimestamp(), "Cert Spotter gives no log timestamp");
        assertTrue(served.names().contains("example.com"));
        assertEquals("certspotter:16164256171", served.ref());
    }

    @Test
    @DisplayName("Queries subdomains and wildcards with DER expanded, and pages with after= until an empty page")
    void pagesUntilEmpty(@TempDir Path dir) throws Exception {
        FakeHttp http = new FakeHttp().then(200, realPage()).then(200, "[]");
        CtFetchResult r = source(http, dir, null).fetch("example.com");
        assertEquals(3, r.entries().size());
        assertEquals(2, http.urls.size());
        String first = http.urls.get(0);
        for (String p : List.of("include_subdomains=true", "match_wildcards=true", "expand=cert_der", "expand=dns_names", "domain=example.com")) {
            assertTrue(first.contains(p), first);
        }
        assertFalse(first.contains("after="));
        assertTrue(http.urls.get(1).endsWith("&after=16164256171"), http.urls.get(1));
        assertEquals("certspotter", r.source());
    }

    @Test
    @DisplayName("An API key goes only in the Authorization header, never in a URL or an error message")
    void apiKeyOnlyInHeader(@TempDir Path dir) {
        FakeHttp http = new FakeHttp().then(403, "{\"code\":\"forbidden\",\"message\":\"bad key\"}");
        CtLookupException e = assertThrows(CtLookupException.class, () -> source(http, dir, "sk_secret123").fetch("example.com"));
        assertEquals(Map.of("Authorization", "Bearer sk_secret123"), http.headers.get(0));
        assertFalse(http.urls.get(0).contains("sk_secret123"));
        assertFalse(e.getMessage().contains("sk_secret123"));
        assertTrue(source(new FakeHttp(), dir, null).authenticated() == false);
    }

    @Test
    @DisplayName("A 429 is reported as received with Retry-After, is not retried, and stops the source for the rest of the run")
    void rateLimitStopsTheSource(@TempDir Path dir) {
        String body = "{\"code\":\"rate_limited\",\"message\":\"You have exceeded the rate limit\"}";
        FakeHttp http = new FakeHttp().then(429, body, Map.of("retry-after", List.of("1800")));
        CertSpotterSource src = source(http, dir, null);
        CtLookupException first = assertThrows(CtLookupException.class, () -> src.fetch("a.example"));
        assertTrue(first.getMessage().startsWith("Cert Spotter HTTP 429 for https://api.certspotter.com/v1/issuances?"), first.getMessage());
        assertTrue(first.getMessage().endsWith("(attempt 1 of 2): " + body + "; Retry-After: 1800"), first.getMessage());
        assertEquals(1, http.urls.size());

        CtLookupException later = assertThrows(CtLookupException.class, () -> src.fetch("b.example"));
        assertEquals(1, http.urls.size(), "no request after the quota ran out");
        assertTrue(later.getMessage().startsWith("Cert Spotter not queried: its rate limit was reached earlier in this run"));
        assertTrue(later.getMessage().contains("rate_limited"));
    }

    @Test
    @DisplayName("A 5xx is retried once and then reported as received")
    void serverErrorRetried(@TempDir Path dir) {
        FakeHttp http = new FakeHttp().then(503, "unavailable").then(502, "<html>bad gateway</html>");
        CtLookupException e = assertThrows(CtLookupException.class, () -> source(http, dir, null).fetch("example.com"));
        assertTrue(e.getMessage().contains("HTTP 502") && e.getMessage().contains("(attempt 2 of 2): <html>bad gateway</html>"), e.getMessage());
    }

    @Test
    @DisplayName("A cert_sha256 that does not match its cert_der fails the source instead of trusting either")
    void shaMismatchIsAnError() {
        String tampered = realPage().replace("6153a96fd1a6ab7f4d438fc34932484299d0729d9140b3a126bb2f9c07b02200",
                "0000000000000000000000000000000000000000000000000000000000000000");
        CtLookupException e = assertThrows(CtLookupException.class, () -> CertSpotterSource.parse("u", tampered));
        assertTrue(e.getMessage().contains("16164256171") && e.getMessage().contains("does not match its cert_der"), e.getMessage());
    }

    @Test
    @DisplayName("More than the page cap is an error, not a silently truncated result")
    void pageCap(@TempDir Path dir) {
        FakeHttp http = new FakeHttp();
        for (int i = 0; i < CertSpotterSource.MAX_PAGES; i++) http.then(200, realPage());
        CtLookupException e = assertThrows(CtLookupException.class, () -> source(http, dir, null).fetch("example.com"));
        assertTrue(e.getMessage().contains("more than " + CertSpotterSource.MAX_PAGES + " pages"));
    }

    @Test
    @DisplayName("A redirect is reported as received and not retried: the Cert Spotter client never follows one with the API key")
    void redirectIsAnError(@TempDir Path dir) {
        FakeHttp http = new FakeHttp().then(301, "", Map.of("location", List.of("https://elsewhere.example/")));
        CtLookupException e = assertThrows(CtLookupException.class, () -> source(http, dir, "sk_secret123").fetch("example.com"));
        assertTrue(e.getMessage().startsWith("Cert Spotter HTTP 301"), e.getMessage());
        assertEquals(1, http.urls.size());
    }
}
