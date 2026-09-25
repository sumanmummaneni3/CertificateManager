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
 * One issuance after CT-02 reconciliation: every entry sharing (issuer, serial), from every source,
 * collapsed into one. RFC 6962 requires a precertificate and its certificate to share that pair.
 *
 * @param firstSeen       the earliest entry timestamp any source gave, or null if none gave one
 * @param refs            every entry, as {@code source:id} (the CT log reference)
 * @param sources         the sources that reported this issuance
 * @param finalCertSha256 SHA-256 of each logged final certificate (not precertificate), when known
 */
public record CtIssuance(String issuerName, String serialHex, String commonName, List<String> names,
                         Instant notBefore, Instant notAfter, Instant firstSeen, List<String> refs,
                         List<String> sources, List<String> finalCertSha256) {

    public boolean validAt(Instant t) {
        return !t.isBefore(notBefore) && t.isBefore(notAfter);
    }

    /** crt.sh entry ids, for the opt-in DER download (only crt.sh serves DER by id). */
    public List<Long> crtShIds() {
        return refs.stream().filter(r -> r.startsWith(CrtShSource.NAME + ":"))
                .map(r -> Long.parseLong(r.substring(CrtShSource.NAME.length() + 1))).toList();
    }

    public String evidence() {
        StringBuilder sb = new StringBuilder();
        for (String r : refs) {
            if (!sb.isEmpty()) sb.append(' ');
            int colon = r.indexOf(':');
            String source = r.substring(0, colon);
            String id = r.substring(colon + 1);
            if (source.equals(CrtShSource.NAME)) sb.append("https://crt.sh/?id=").append(id);
            else sb.append("Cert Spotter issuance ").append(id);
        }
        if (!finalCertSha256.isEmpty()) sb.append(" (cert_sha256 ").append(String.join(", ", finalCertSha256)).append(')');
        return sb.toString();
    }
}
