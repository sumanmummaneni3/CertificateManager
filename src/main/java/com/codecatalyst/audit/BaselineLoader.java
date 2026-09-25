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

package com.codecatalyst.audit;

import com.codecatalyst.audit.served.BaselineObservation;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/** Reads a previous run's {@code audit-<ts>.json} for CHN-02 (D2/D8). */
public final class BaselineLoader {

    public record Baseline(List<BaselineObservation> observations, Map<String, String> subjectBySha, Path source) {}

    private BaselineLoader() {}

    public static Baseline load(Path json) throws IOException {
        JsonNode root = new ObjectMapper().readTree(Files.readString(json));
        if (root == null || !root.has("observations")) {
            throw new IOException(json + " is not an audit JSON export (no 'observations')");
        }
        List<BaselineObservation> obs = new ArrayList<>();
        for (JsonNode o : root.path("observations")) {
            if (!o.path("reachable").asBoolean(false)) continue;
            List<String> chain = new ArrayList<>();
            o.path("chainSha256").forEach(n -> chain.add(n.asText()));
            obs.add(new BaselineObservation(o.path("host").asText(), o.path("port").asInt(),
                    o.path("address").asText(), o.path("leafSha256").asText(), o.path("chainHash").asText(),
                    chain, Instant.parse(o.path("observedAt").asText())));
        }
        Map<String, String> subjects = new HashMap<>();
        root.path("certificates").fields().forEachRemaining(e -> subjects.put(e.getKey(), e.getValue().path("subject").asText()));
        return new Baseline(obs, subjects, json);
    }
}
