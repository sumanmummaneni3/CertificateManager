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

import java.nio.file.Path;
import java.util.Locale;

/**
 * {@code -audit} options (D1, amended by D8). {@code --csv}, {@code --requester} and {@code --basis}
 * are required: every run records who asked for it and on what basis (RPT-02).
 */
public record AuditOptions(Path csv, Path outDir, Path baseline, String resolver, int concurrency,
                           String requester, Basis basis, int ctCacheTtlHours, boolean ctFetchDer,
                           java.util.List<String> ctSources) {

    /** CLI names of the CT sources, in query order (D14). */
    public static final java.util.List<String> CT_SOURCES = java.util.List.of("crtsh", "certspotter");

    /** Why the operator may look at these domains. {@code PUBLIC_PROSPECT} is CT, DNS and one handshake only. */
    public enum Basis { OWN, CONSENT, PUBLIC_PROSPECT }

    public static final String USAGE = "-audit --csv <file> --requester <name> --basis <OWN|CONSENT|PUBLIC_PROSPECT>"
            + " [--out <dir>] [--baseline <previous audit json>] [--resolver <ip>] [--concurrency <n>]"
            + " [--ct-cache-ttl <hours>] [--ct-fetch-der] [--ct-sources crtsh,certspotter]";

    /** Parses the arguments after {@code -audit}. */
    public static AuditOptions parse(String[] args, int start) {
        Path csv = null;
        Path out = Path.of(".");
        Path baseline = null;
        String resolver = "8.8.8.8";
        int concurrency = 4;
        String requester = null;
        Basis basis = null;
        int ttl = 6;
        boolean der = false;
        java.util.List<String> sources = CT_SOURCES;

        for (int i = start; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--csv" -> csv = Path.of(value(args, ++i, a));
                case "--out" -> out = Path.of(value(args, ++i, a));
                case "--baseline" -> baseline = Path.of(value(args, ++i, a));
                case "--resolver" -> resolver = value(args, ++i, a);
                case "--concurrency" -> concurrency = intValue(args, ++i, a, 1, 32);
                case "--requester" -> requester = value(args, ++i, a).trim();
                case "--basis" -> {
                    String v = value(args, ++i, a);
                    try {
                        basis = Basis.valueOf(v.toUpperCase(Locale.ROOT));
                    } catch (IllegalArgumentException e) {
                        throw new IllegalArgumentException("--basis must be OWN, CONSENT or PUBLIC_PROSPECT, not '" + v + "'");
                    }
                }
                case "--ct-cache-ttl" -> ttl = intValue(args, ++i, a, 0, 24 * 30);
                case "--ct-fetch-der" -> der = true;
                case "--ct-sources" -> {
                    String v = value(args, ++i, a);
                    java.util.LinkedHashSet<String> picked = new java.util.LinkedHashSet<>();
                    for (String part : v.split(",")) {
                        String p = part.trim().toLowerCase(Locale.ROOT);
                        if (!CT_SOURCES.contains(p)) {
                            throw new IllegalArgumentException("--ct-sources takes crtsh and/or certspotter, not '" + part.trim() + "'");
                        }
                        picked.add(p);
                    }
                    sources = CT_SOURCES.stream().filter(picked::contains).toList();
                }
                default -> throw new IllegalArgumentException("Unknown -audit option: " + a);
            }
        }
        if (csv == null) throw new IllegalArgumentException("-audit requires --csv <file>");
        if (requester == null || requester.isEmpty()) throw new IllegalArgumentException("-audit requires --requester <name>");
        if (basis == null) throw new IllegalArgumentException("-audit requires --basis <OWN|CONSENT|PUBLIC_PROSPECT>");
        return new AuditOptions(csv, out, baseline, resolver, concurrency, requester, basis, ttl, der, sources);
    }

    private static String value(String[] args, int i, String flag) {
        if (i >= args.length || args[i].startsWith("--")) {
            throw new IllegalArgumentException(flag + " needs a value");
        }
        return args[i];
    }

    private static int intValue(String[] args, int i, String flag, int min, int max) {
        String v = value(args, i, flag);
        try {
            int n = Integer.parseInt(v);
            if (n < min || n > max) throw new NumberFormatException();
            return n;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(flag + " must be a whole number from " + min + " to " + max + ", not '" + v + "'");
        }
    }
}
