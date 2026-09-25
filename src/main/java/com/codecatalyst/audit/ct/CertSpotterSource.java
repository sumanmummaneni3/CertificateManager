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

import com.codecatalyst.audit.served.CertFingerprints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.*;

/**
 * SSLMate's Cert Spotter API, the second CT source (D14). It answered while crt.sh was down all of
 * 2026-09-25. It returns only unexpired certificates, which is what CT-03 judges, and each entry's
 * DER, from which serial and issuer are read exactly. It has no serial field of its own.
 *
 * <p>Anonymous use allows 10 requests (per hour, per its docs); paging ends on an empty page, so a
 * domain costs at least two. An API key from the {@code CERTSPOTTER_API_KEY} environment variable
 * is sent as a Bearer token and is never written anywhere. After a 429 the source stops for the
 * rest of the run, and each later domain's error quotes the original response.
 */
public class CertSpotterSource implements CtLogSource {

    public static final String NAME = "certspotter";
    static final int MAX_PAGES = 50;
    private static final String BASE = "https://api.certspotter.com/v1/issuances?include_subdomains=true"
            + "&match_wildcards=true&expand=dns_names&expand=issuer&expand=cert_der&domain=";
    private static final String POISON_OID = "1.3.6.1.4.1.11129.2.4.3";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int ATTEMPTS = 2;

    private final HttpFetcher http;
    private final RateGate gate;
    private final CtCache cache;
    private final Clock clock;
    private final String apiKey;
    private volatile String rateLimited;

    /** @param apiKey null or blank for anonymous use */
    public CertSpotterSource(HttpFetcher http, RateGate gate, CtCache cache, Clock clock, String apiKey) {
        this.http = http;
        this.gate = gate;
        this.cache = cache;
        this.clock = clock;
        this.apiKey = (apiKey == null || apiKey.isBlank()) ? null : apiKey.trim();
    }

    @Override
    public String name() {
        return NAME;
    }

    public boolean authenticated() {
        return apiKey != null;
    }

    @Override
    public CtFetchResult fetch(String domain) throws CtLookupException, InterruptedException {
        if (rateLimited != null) {
            throw new CtLookupException("Cert Spotter not queried: its rate limit was reached earlier in this run — "
                    + rateLimited);
        }
        Map<String, CtEntry> byId = new LinkedHashMap<>();
        List<String> urls = new ArrayList<>();
        Instant oldest = null;
        boolean anyCached = false;
        String after = null;
        for (int page = 0; ; page++) {
            if (page == MAX_PAGES) {
                throw new CtLookupException("Cert Spotter returned more than " + MAX_PAGES + " pages for " + domain
                        + "; stopping rather than report an incomplete result");
            }
            String url = BASE + URLEncoder.encode(domain, StandardCharsets.UTF_8)
                    + (after == null ? "" : "&after=" + URLEncoder.encode(after, StandardCharsets.UTF_8));
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
                entries = parse(url, body); // throws before caching if unreadable
                cache.put(url, body, at);
            }
            oldest = (oldest == null || at.isBefore(oldest)) ? at : oldest;
            if (entries.isEmpty()) break;
            for (CtEntry e : entries) byId.putIfAbsent(e.entryId(), e);
            after = entries.get(entries.size() - 1).entryId();
        }
        return new CtFetchResult(NAME, List.copyOf(byId.values()), oldest, anyCached, urls);
    }

    private byte[] getWithRetry(String url) throws CtLookupException, InterruptedException {
        Map<String, String> headers = apiKey == null ? Map.of() : Map.of("Authorization", "Bearer " + apiKey);
        String last = null;
        for (int attempt = 1; attempt <= ATTEMPTS; attempt++) {
            gate.acquire();
            try {
                HttpFetcher.Response r = http.get(URI.create(url), headers);
                if (r.status() == 200) return r.body();
                last = "Cert Spotter HTTP " + r.status() + " for " + url + " (attempt " + attempt + " of " + ATTEMPTS
                        + "): " + CrtShSource.snippet(r.body())
                        + r.header("Retry-After").map(v -> "; Retry-After: " + v).orElse("");
                if (r.status() == 429) {
                    rateLimited = last;
                    break;
                }
                if (r.status() < 500) break; // a 4xx will not change on retry
            } catch (IOException e) {
                last = "Cert Spotter request failed for " + url + " (attempt " + attempt + " of " + ATTEMPTS + "): "
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
            throw new CtLookupException("Cert Spotter returned non-JSON body for " + url + ": "
                    + CrtShSource.snippet(body.getBytes(StandardCharsets.UTF_8)));
        }
        if (root == null || !root.isArray()) {
            throw new CtLookupException("Cert Spotter returned JSON that is not an array for " + url + ": "
                    + CrtShSource.snippet(body.getBytes(StandardCharsets.UTF_8)));
        }
        List<CtEntry> out = new ArrayList<>();
        for (JsonNode n : root) {
            String id = n.path("id").asText();
            try {
                byte[] der = Base64.getDecoder().decode(n.path("cert_der").asText());
                X509Certificate c = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(der));
                String sha = n.path("cert_sha256").asText();
                if (!CertFingerprints.sha256(der).equals(sha)) {
                    throw new IllegalArgumentException("cert_sha256 " + sha + " does not match its cert_der");
                }
                List<String> names = new ArrayList<>();
                n.path("dns_names").forEach(x -> {
                    String t = x.asText().trim().toLowerCase(Locale.ROOT);
                    if (!t.isEmpty() && !names.contains(t)) names.add(t);
                });
                out.add(new CtEntry(NAME, id, c.getIssuerX500Principal().getName(), c.getSerialNumber().toString(16),
                        cn(c), names, c.getNotBefore().toInstant(), c.getNotAfter().toInstant(), null, sha,
                        c.getExtensionValue(POISON_OID) != null));
            } catch (Exception e) {
                throw new CtLookupException("Cert Spotter issuance " + id + " could not be read for " + url + ": "
                        + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
        return out;
    }

    private static String cn(X509Certificate c) {
        for (String part : c.getSubjectX500Principal().getName().split(",")) {
            if (part.trim().startsWith("CN=")) return part.trim().substring(3);
        }
        return "";
    }
}
