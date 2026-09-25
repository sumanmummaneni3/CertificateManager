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
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * On-disk cache of successful crt.sh answers (CT-01 "cache results", D8), keyed by the URL's hash
 * and stamped with the fetch time so the report can say how old a cached answer was. Failures are
 * never cached.
 */
public class CtCache {

    public record Cached(String body, Instant fetchedAt) {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path dir;
    private final Duration ttl;
    private final Clock clock;

    public CtCache(Path dir, Duration ttl, Clock clock) {
        this.dir = dir;
        this.ttl = ttl;
        this.clock = clock;
    }

    public boolean enabled() {
        return !ttl.isZero() && !ttl.isNegative();
    }

    public Optional<Cached> get(String url) {
        if (!enabled()) return Optional.empty();
        Path f = file(url);
        if (!Files.isRegularFile(f)) return Optional.empty();
        try {
            JsonNode n = MAPPER.readTree(Files.readString(f, StandardCharsets.UTF_8));
            if (!url.equals(n.path("url").asText())) return Optional.empty();
            Instant at = Instant.parse(n.path("fetchedAt").asText());
            if (at.plus(ttl).isBefore(clock.instant())) return Optional.empty();
            return Optional.of(new Cached(n.path("body").asText(), at));
        } catch (IOException | RuntimeException e) {
            return Optional.empty(); // a damaged cache entry is just a miss
        }
    }

    public void put(String url, String body, Instant fetchedAt) {
        if (!enabled()) return;
        try {
            Files.createDirectories(dir);
            ObjectNode n = MAPPER.createObjectNode();
            n.put("url", url);
            n.put("fetchedAt", fetchedAt.toString());
            n.put("body", body);
            Path tmp = Files.createTempFile(dir, "ct", ".tmp");
            Files.writeString(tmp, MAPPER.writeValueAsString(n), StandardCharsets.UTF_8);
            Files.move(tmp, file(url), java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            System.err.println("Warning: could not write CT cache entry: " + e.getMessage());
        }
    }

    private Path file(String url) {
        return dir.resolve(CertFingerprints.sha256(url.getBytes(StandardCharsets.UTF_8)) + ".json");
    }
}
