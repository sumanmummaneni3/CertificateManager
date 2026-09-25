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

package com.codecatalyst.audit.caa;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** One CAA property as found in DNS (CAA-01: all parameters are recorded). */
public record CaaProperty(int flags, String tag, String value) {

    public boolean critical() {
        return (flags & 0x80) != 0;
    }

    public boolean isIssueTag() {
        String t = tag.toLowerCase(Locale.ROOT);
        return t.equals("issue") || t.equals("issuewild");
    }

    /** The CA domain of an issue/issuewild value; empty for {@code ";"}, which forbids issuance. */
    public String issuerDomain() {
        int semi = value.indexOf(';');
        return (semi < 0 ? value : value.substring(0, semi)).trim().toLowerCase(Locale.ROOT);
    }

    /** The {@code key=value} parameters after the CA domain (RFC 8659 §4.2), keys lower-cased. */
    public Map<String, String> parameters() {
        Map<String, String> out = new LinkedHashMap<>();
        int semi = value.indexOf(';');
        if (semi < 0) return out;
        for (String p : value.substring(semi + 1).split(";")) {
            String t = p.trim();
            int eq = t.indexOf('=');
            if (eq <= 0) continue;
            out.put(t.substring(0, eq).trim().toLowerCase(Locale.ROOT), t.substring(eq + 1).trim());
        }
        return out;
    }
}
