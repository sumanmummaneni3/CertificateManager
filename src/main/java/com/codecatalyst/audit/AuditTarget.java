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

import java.util.Map;

/**
 * One CSV row (INT-04, D8).
 *
 * @param host   the name to resolve and handshake with (SNI)
 * @param port   the only port contacted for this host
 * @param domain registrable domain from the CSV, or null when the column was blank
 * @param owner  owner from the CSV, or empty
 * @param tags   tags from the CSV
 * @param line   the CSV line the row came from
 */
public record AuditTarget(String host, int port, String domain, String owner,
                          Map<String, String> tags, int line) {

    /** The CT query unit: the declared domain, or the host itself when none was given. */
    public String ctDomain() {
        return domain != null ? domain : host;
    }

    /** {@code DOMAIN} when the CSV declared a domain, else {@code HOST_ONLY} (no public suffix list, D8). */
    public String ctScope() {
        return domain != null ? "DOMAIN" : "HOST_ONLY";
    }

    public String hostPort() {
        return host + ":" + port;
    }
}
