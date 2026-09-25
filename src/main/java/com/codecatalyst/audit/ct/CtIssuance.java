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
 * One issuance after CT-02 reconciliation: every log entry sharing (issuer, serial), which RFC 6962
 * requires of a precertificate and its final certificate, collapsed into one.
 *
 * @param crtShIds  every crt.sh entry id that makes up this issuance (the CT log reference)
 * @param firstSeen the earliest entry timestamp
 */
public record CtIssuance(String issuerName, String serialHex, String commonName, List<String> names,
                         Instant notBefore, Instant notAfter, Instant firstSeen, List<Long> crtShIds) {

    public boolean validAt(Instant t) {
        return !t.isBefore(notBefore) && t.isBefore(notAfter);
    }

    public String evidence() {
        StringBuilder sb = new StringBuilder();
        for (long id : crtShIds) {
            if (!sb.isEmpty()) sb.append(' ');
            sb.append("https://crt.sh/?id=").append(id);
        }
        return sb.toString();
    }
}
