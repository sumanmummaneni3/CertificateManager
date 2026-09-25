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

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Compares an issuer DN as crt.sh renders it ({@code C=US, O=Let's Encrypt, CN=R11}) with one as
 * Java renders it ({@code CN=R11,O=Let's Encrypt,C=US}). Order and spacing differ, and Java
 * hex-encodes attributes it has no keyword for (e.g. emailAddress), so the comparison is over the
 * named attributes both sides carry, and requires CN to be among them.
 */
public final class IssuerNames {

    private IssuerNames() {}

    public static boolean same(String a, String b) {
        Map<String, String> x = attrs(a);
        Map<String, String> y = attrs(b);
        if (x == null || y == null) return norm(a).equals(norm(b));
        if (!x.containsKey("CN") || !y.containsKey("CN")) return x.equals(y);
        int compared = 0;
        for (var e : x.entrySet()) {
            String other = y.get(e.getKey());
            if (other == null) continue;
            if (!other.equals(e.getValue())) return false;
            compared++;
        }
        return compared > 0;
    }

    /** A stable key for grouping, used for CT-02 reconciliation of crt.sh's own strings. */
    public static String key(String dn) {
        Map<String, String> m = attrs(dn);
        if (m == null) return norm(dn);
        return new java.util.TreeMap<>(m).toString();
    }

    private static Map<String, String> attrs(String dn) {
        try {
            Map<String, String> m = new HashMap<>();
            for (Rdn r : new LdapName(dn).getRdns()) {
                String type = r.getType().toUpperCase(Locale.ROOT);
                Object v = r.getValue();
                if (!(v instanceof String s) || !type.chars().allMatch(Character::isLetter)) continue;
                m.put(type, norm(s));
            }
            return m;
        } catch (InvalidNameException | IllegalArgumentException e) {
            return null;
        }
    }

    private static String norm(String s) {
        return s == null ? "" : s.trim().replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
    }
}
