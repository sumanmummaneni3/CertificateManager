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

import java.time.Instant;
import java.util.List;

/**
 * One CT search result from one source (D14): a log entry, which may be a precertificate or the
 * final certificate.
 *
 * @param source         {@code crt.sh} or {@code certspotter}
 * @param entryId        the source's own id for the entry
 * @param entryTimestamp when the entry was logged, or null when the source does not say (Cert Spotter)
 * @param certSha256     SHA-256 of the logged DER, or null when the source does not give it (crt.sh)
 * @param precert        true for a precertificate, false for a final certificate, null when unknown
 */
public record CtEntry(String source, String entryId, String issuerName, String serialHex, String commonName,
                      List<String> names, Instant notBefore, Instant notAfter, Instant entryTimestamp,
                      String certSha256, Boolean precert) {

    public String ref() {
        return source + ":" + entryId;
    }
}
