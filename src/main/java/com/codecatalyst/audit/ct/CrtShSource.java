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

package com.codecatalyst.audit.ct;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

/**
 * crt.sh, the only CT source (D8). Two queries per domain ({@code q=domain} and {@code q=%.domain})
 * cover the name and its subdomains. One retry on a 5xx or I/O failure, then the failure is raised
 * with the status code and body <b>as received</b> — the user's decision after crt.sh answered 502
 * during design: report it, do not mask it with a fallback provider.
 */
public class CrtShSource implements CtLogSource {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int ATTEMPTS = 2;

    private final HttpFetcher http;
    private final RateGate gate;
    private final CtCache cache;
    private final Clock clock;

    public CrtShSource(HttpFetcher http, RateGate gate, CtCache cache, Clock clock) {
        this.http = http;
        this.gate = gate;
        this.cache = cache;
        this.clock = clock;
    }

    @Override
    public CtFetchResult fetch(String domain) throws CtLookupException, InterruptedException {
        Map<Long, CtEntry> byId = new LinkedHashMap<>();
        Instant oldest = null;
        boolean anyCached = false;
        List<String> urls = new ArrayList<>();
        for (String q : List.of(domain, "%." + domain)) {
            String url = "https://crt.sh/?q=" + URLEncoder.encode(q, StandardCharsets.UTF_8) + "&output=json";
            urls.add(url);
            List<CtEntry> entries;
            Instant at;
            Optional<CtCache.Cached> hit = cache.get(url);
            if (hit.isPresent()) {
                entries = parse(url, hit.get().body());
                at = hit.get().fetchedAt();
                anyCached = true;
            } else {
                String body = new String(getWithRetry(url), StandardCharsets.UTF_8);
                at = clock.instant();
                entries = parse(url, body); // throws before caching if it is not JSON
                cache.put(url, body, at);
            }
            for (CtEntry e : entries) byId.putIfAbsent(e.crtShId(), e);
            oldest = (oldest == null || at.isBefore(oldest)) ? at : oldest;
        }
        return new CtFetchResult(List.copyOf(byId.values()), oldest, anyCached, urls);
    }

    @Override
    public byte[] fetchDer(long entryId) throws CtLookupException, InterruptedException {
        return getWithRetry("https://crt.sh/?d=" + entryId);
    }

    private byte[] getWithRetry(String url) throws CtLookupException, InterruptedException {
        String last = null;
        for (int attempt = 1; attempt <= ATTEMPTS; attempt++) {
            gate.acquire();
            try {
                HttpFetcher.Response r = http.get(URI.create(url));
                if (r.status() == 200) return r.body();
                last = "crt.sh HTTP " + r.status() + " for " + url + " (attempt " + attempt + " of " + ATTEMPTS + "): "
                        + snippet(r.body());
                if (r.status() < 500) break; // a 4xx will not change on retry
            } catch (IOException e) {
                last = "crt.sh request failed for " + url + " (attempt " + attempt + " of " + ATTEMPTS + "): "
                        + e.getClass().getSimpleName() + ": " + e.getMessage();
            }
        }
        throw new CtLookupException(last);
    }

    static List<CtEntry> parse(String url, String body) throws CtLookupException {
        JsonNode root;
        try {
            root = MAPPER.readTree(body);
        } catch (IOException e) {
            throw new CtLookupException("crt.sh returned non-JSON body for " + url + ": "
                    + snippet(body.getBytes(StandardCharsets.UTF_8)));
        }
        if (root == null || !root.isArray()) {
            throw new CtLookupException("crt.sh returned JSON that is not an array for " + url + ": "
                    + snippet(body.getBytes(StandardCharsets.UTF_8)));
        }
        List<CtEntry> out = new ArrayList<>();
        for (JsonNode n : root) {
            try {
                List<String> names = new ArrayList<>();
                for (String s : n.path("name_value").asText().split("\n")) {
                    String t = s.trim().toLowerCase(Locale.ROOT);
                    if (!t.isEmpty() && !names.contains(t)) names.add(t);
                }
                String serial = n.path("serial_number").asText().toLowerCase(Locale.ROOT);
                new java.math.BigInteger(serial, 16); // rejects a missing or non-hex serial here, not later
                out.add(new CtEntry(n.path("id").asLong(),
                        n.path("issuer_name").asText(),
                        serial,
                        n.path("common_name").asText(),
                        names,
                        utc(n.path("not_before").asText()),
                        utc(n.path("not_after").asText()),
                        utc(n.path("entry_timestamp").asText())));
            } catch (RuntimeException e) {
                throw new CtLookupException("crt.sh row could not be read for " + url + ": " + e.getMessage()
                        + " — row: " + snippet(n.toString().getBytes(StandardCharsets.UTF_8)));
            }
        }
        return out;
    }

    /** crt.sh timestamps are UTC with no zone designator. */
    private static Instant utc(String s) {
        return LocalDateTime.parse(s).toInstant(ZoneOffset.UTC);
    }

    static String snippet(byte[] body) {
        if (body == null || body.length == 0) return "(empty body)";
        String s = new String(body, StandardCharsets.UTF_8).replaceAll("\\s+", " ").trim();
        return s.length() > 200 ? s.substring(0, 200) + "…" : s;
    }
}
