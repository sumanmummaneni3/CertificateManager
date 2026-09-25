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

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Minimal HTTP GET seam so CT sources can be tested without the network. */
@FunctionalInterface
public interface HttpFetcher {

    /** @param headers response headers, names lower-cased */
    record Response(int status, byte[] body, Map<String, List<String>> headers) {
        public Response(int status, byte[] body) {
            this(status, body, Map.of());
        }

        public Optional<String> header(String name) {
            List<String> v = headers.get(name.toLowerCase(java.util.Locale.ROOT));
            return v == null || v.isEmpty() ? Optional.empty() : Optional.of(v.get(0));
        }
    }

    /** @param requestHeaders extra request headers, e.g. {@code Authorization}; never logged */
    Response get(URI uri, Map<String, String> requestHeaders) throws IOException, InterruptedException;

    default Response get(URI uri) throws IOException, InterruptedException {
        return get(uri, Map.of());
    }

    /**
     * The real client. Every request carries an identifying User-Agent (NFR-03). crt.sh answers for
     * large domains routinely take tens of seconds, hence the 30s request timeout.
     */
    static HttpFetcher live(String userAgent) {
        return live(userAgent, HttpClient.Redirect.NORMAL);
    }

    /**
     * @param redirects {@code NEVER} for any client that sends credentials (Cert Spotter's API key):
     *                  a followed redirect to another host could carry the {@code Authorization}
     *                  header with it, so a 3xx is reported as received instead (D14 review)
     */
    static HttpFetcher live(String userAgent, HttpClient.Redirect redirects) {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(redirects)
                .build();
        return (uri, requestHeaders) -> {
            HttpRequest.Builder req = HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofSeconds(30))
                    .header("User-Agent", userAgent)
                    .GET();
            requestHeaders.forEach(req::header);
            HttpResponse<byte[]> resp = client.send(req.build(), HttpResponse.BodyHandlers.ofByteArray());
            Map<String, List<String>> headers = new java.util.HashMap<>();
            resp.headers().map().forEach((k, v) -> headers.put(k.toLowerCase(java.util.Locale.ROOT), v));
            return new Response(resp.statusCode(), resp.body(), headers);
        };
    }
}
