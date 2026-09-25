package com.codecatalyst.audit.ct;

import com.codecatalyst.audit.TestCerts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.ArrayDeque;

import static org.junit.jupiter.api.Assertions.*;

class CrtShSourceTest {

    static final String ROW = """
            {"issuer_ca_id":295815,"issuer_name":"C=US, O=Let's Encrypt, CN=R11","common_name":"www.example.com",
             "name_value":"example.com\\nwww.example.com","id":%d,"entry_timestamp":"2026-09-01T10:00:00.123",
             "not_before":"2026-09-01T09:00:00","not_after":"2026-11-30T09:00:00","serial_number":"%s","result_count":2}""";

    static String row(long id, String serial) {
        return ROW.formatted(id, serial);
    }

    private static final Clock CLOCK = Clock.fixed(TestCerts.NOW, ZoneOffset.UTC);

    /** Answers from a queue and records every URL asked for. */
    static final class FakeHttp implements HttpFetcher {
        final Deque<Object> answers = new ArrayDeque<>();
        final List<String> urls = new ArrayList<>();

        FakeHttp then(int status, String body) { answers.add(new Response(status, body.getBytes(StandardCharsets.UTF_8))); return this; }
        FakeHttp thenThrow(IOException e) { answers.add(e); return this; }

        @Override
        public Response get(URI uri, java.util.Map<String, String> headers) throws IOException {
            urls.add(uri.toString());
            Object a = answers.poll();
            if (a == null) throw new AssertionError("unexpected request " + uri);
            if (a instanceof IOException e) throw e;
            return (Response) a;
        }
    }

    private CrtShSource source(FakeHttp http, Path cacheDir, int ttlHours) {
        return new CrtShSource(http, new RateGate(0), new CtCache(cacheDir, Duration.ofHours(ttlHours), CLOCK), CLOCK);
    }

    @Test
    @DisplayName("Queries the name and %.name (URL-encoded), and merges entries by crt.sh id")
    void queriesNameAndSubdomains(@TempDir Path dir) throws Exception {
        FakeHttp http = new FakeHttp().then(200, "[" + row(1, "0a") + "]").then(200, "[" + row(1, "0a") + "," + row(2, "0b") + "]");
        CtFetchResult r = source(http, dir, 0).fetch("example.com");
        assertEquals(List.of("https://crt.sh/?q=example.com&output=json", "https://crt.sh/?q=%25.example.com&output=json"), http.urls);
        assertEquals(2, r.entries().size());
        assertEquals(List.of("example.com", "www.example.com"), r.entries().get(0).names());
        assertFalse(r.fromCache());
    }

    @Test
    @DisplayName("A 502 on both attempts is reported with the status code, URL, attempt count and body as received")
    void badGatewayReportedVerbatim(@TempDir Path dir) {
        String nginx = "<html>\n<head><title>502 Bad Gateway</title></head>\n<body></body></html>";
        FakeHttp http = new FakeHttp().then(502, nginx).then(502, nginx);
        CtLookupException e = assertThrows(CtLookupException.class, () -> source(http, dir, 0).fetch("example.com"));
        assertEquals("crt.sh HTTP 502 for https://crt.sh/?q=example.com&output=json (attempt 2 of 2): "
                + "<html> <head><title>502 Bad Gateway</title></head> <body></body></html>", e.getMessage());
    }

    @Test
    @DisplayName("A 5xx followed by a 200 succeeds on the retry")
    void retriesOnce(@TempDir Path dir) throws Exception {
        FakeHttp http = new FakeHttp().then(503, "busy").then(200, "[]").then(200, "[]");
        assertTrue(source(http, dir, 0).fetch("example.com").entries().isEmpty());
        assertEquals(3, http.urls.size());
    }

    @Test
    @DisplayName("A 4xx is not retried")
    void noRetryOn4xx(@TempDir Path dir) {
        FakeHttp http = new FakeHttp().then(429, "slow down");
        CtLookupException e = assertThrows(CtLookupException.class, () -> source(http, dir, 0).fetch("example.com"));
        assertTrue(e.getMessage().startsWith("crt.sh HTTP 429"));
        assertTrue(e.getMessage().contains("(attempt 1 of 2): slow down"));
    }

    @Test
    @DisplayName("An I/O failure is reported with its exception type and message")
    void ioFailure(@TempDir Path dir) {
        FakeHttp http = new FakeHttp().thenThrow(new java.net.http.HttpTimeoutException("request timed out"))
                .thenThrow(new java.net.ConnectException("Connection refused"));
        CtLookupException e = assertThrows(CtLookupException.class, () -> source(http, dir, 0).fetch("example.com"));
        assertTrue(e.getMessage().endsWith("(attempt 2 of 2): ConnectException: Connection refused"), e.getMessage());
    }

    @Test
    @DisplayName("A 200 with an HTML body is an error naming the body, not an empty result")
    void nonJsonIsAnError(@TempDir Path dir) {
        FakeHttp http = new FakeHttp().then(200, "<html>maintenance</html>");
        CtLookupException e = assertThrows(CtLookupException.class, () -> source(http, dir, 6).fetch("example.com"));
        assertTrue(e.getMessage().startsWith("crt.sh returned non-JSON body"), e.getMessage());
    }

    @Test
    @DisplayName("A cached answer is reused within the TTL with its original fetch time; failures are never cached")
    void cache(@TempDir Path dir) throws Exception {
        FakeHttp first = new FakeHttp().then(200, "[" + row(1, "0a") + "]").then(200, "[]");
        source(first, dir, 6).fetch("example.com");
        FakeHttp second = new FakeHttp(); // no answers: any live request fails the test
        CtFetchResult r = source(second, dir, 6).fetch("example.com");
        assertTrue(r.fromCache());
        assertEquals(TestCerts.NOW, r.fetchedAt());
        assertEquals(1, r.entries().size());

        FakeHttp failing = new FakeHttp().then(502, "x").then(502, "x");
        assertThrows(CtLookupException.class, () -> source(failing, dir, 6).fetch("other.example"));
        FakeHttp afterFailure = new FakeHttp().then(200, "[]").then(200, "[]");
        assertFalse(source(afterFailure, dir, 6).fetch("other.example").fromCache());
    }

    @Test
    @DisplayName("A row with no usable serial is an error, not a silently dropped certificate")
    void badRow() {
        CtLookupException e = assertThrows(CtLookupException.class,
                () -> CrtShSource.parse("u", "[" + row(1, "") + "]"));
        assertTrue(e.getMessage().startsWith("crt.sh row could not be read"));
    }
}
