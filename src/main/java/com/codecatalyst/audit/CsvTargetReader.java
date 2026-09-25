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

import com.codecatalyst.CertManager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.util.*;

/**
 * Reads the audit target CSV (INT-04, D8). A header row is required and columns are matched by
 * name, case-insensitively: {@code host} (required), {@code port}, {@code domain}, {@code owner},
 * {@code tags}. A bad row is reported and skipped, never a whole-file rejection. Fields may be
 * double-quoted because Excel quotes any cell containing a comma.
 */
public final class CsvTargetReader {

    public record RowError(int line, String rawLine, String reason) {}

    public record CsvReadResult(List<AuditTarget> targets, List<RowError> errors) {}

    private static final Set<String> KNOWN = Set.of("host", "port", "domain", "owner", "tags");

    public CsvReadResult read(Path csv) throws IOException {
        return parse(Files.readAllLines(csv, StandardCharsets.UTF_8));
    }

    public CsvReadResult parse(List<String> lines) {
        List<AuditTarget> targets = new ArrayList<>();
        List<RowError> errors = new ArrayList<>();

        int headerIdx = -1;
        for (int i = 0; i < lines.size(); i++) {
            if (!stripBom(lines.get(i)).isBlank()) { headerIdx = i; break; }
        }
        if (headerIdx < 0) {
            errors.add(new RowError(0, "", "file is empty"));
            return new CsvReadResult(targets, errors);
        }

        List<String> header;
        try {
            header = splitRow(stripBom(lines.get(headerIdx)));
        } catch (IllegalArgumentException e) {
            errors.add(new RowError(headerIdx + 1, lines.get(headerIdx), "header: " + e.getMessage()));
            return new CsvReadResult(targets, errors);
        }
        Map<String, Integer> col = new HashMap<>();
        for (int c = 0; c < header.size(); c++) {
            String name = header.get(c).trim().toLowerCase(Locale.ROOT);
            if (KNOWN.contains(name)) col.putIfAbsent(name, c);
        }
        if (!col.containsKey("host")) {
            errors.add(new RowError(headerIdx + 1, lines.get(headerIdx),
                    "header row must name a 'host' column (columns: host, port, domain, owner, tags)"));
            return new CsvReadResult(targets, errors);
        }

        Map<String, Integer> seen = new HashMap<>();
        for (int i = headerIdx + 1; i < lines.size(); i++) {
            String raw = lines.get(i);
            int lineNo = i + 1;
            if (raw.isBlank()) continue;
            try {
                List<String> cells = splitRow(raw);
                String host = normaliseName(cell(cells, col.get("host")));
                if (host.isEmpty()) throw new IllegalArgumentException("host is blank");
                if (host.contains(" ") || host.contains("/") || host.contains(":")) {
                    throw new IllegalArgumentException("host '" + host + "' is not a hostname or IPv4 address");
                }
                String portCell = cell(cells, col.get("port")).trim();
                int port;
                try {
                    port = portCell.isEmpty() ? 443 : CertManager.parsePorts(portCell);
                } catch (CertificateException e) {
                    throw new IllegalArgumentException(e.getMessage());
                }
                String domain = normaliseName(cell(cells, col.get("domain")));
                if (!domain.isEmpty() && !(host.equals(domain) || host.endsWith("." + domain))) {
                    throw new IllegalArgumentException("host '" + host + "' is not under domain '" + domain + "'");
                }
                String owner = cell(cells, col.get("owner")).trim();
                Map<String, String> tags = parseTags(cell(cells, col.get("tags")));

                String key = host + ":" + port;
                Integer first = seen.putIfAbsent(key, lineNo);
                if (first != null) {
                    errors.add(new RowError(lineNo, raw, "duplicate of line " + first + " (" + key
                            + "); merged, scanned once"));
                    continue;
                }
                targets.add(new AuditTarget(host, port, domain.isEmpty() ? null : domain, owner, tags, lineNo));
            } catch (IllegalArgumentException e) {
                errors.add(new RowError(lineNo, raw, e.getMessage()));
            }
        }
        return new CsvReadResult(targets, errors);
    }

    private static String cell(List<String> cells, Integer idx) {
        if (idx == null || idx >= cells.size()) return "";
        return cells.get(idx);
    }

    private static String normaliseName(String s) {
        String t = s.trim().toLowerCase(Locale.ROOT);
        return t.endsWith(".") ? t.substring(0, t.length() - 1) : t;
    }

    private static String stripBom(String s) {
        return s.startsWith("﻿") ? s.substring(1) : s;
    }

    static Map<String, String> parseTags(String cell) {
        Map<String, String> tags = new LinkedHashMap<>();
        for (String part : cell.split(";")) {
            String p = part.trim();
            if (p.isEmpty()) continue;
            int eq = p.indexOf('=');
            if (eq <= 0) throw new IllegalArgumentException("tag '" + p + "' is not key=value");
            tags.put(p.substring(0, eq).trim(), p.substring(eq + 1).trim());
        }
        return tags;
    }

    /** Splits one CSV line; {@code "a,b"} is one field and {@code ""} inside quotes is a quote. */
    static List<String> splitRow(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (quoted) {
                if (ch == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') { cur.append('"'); i++; }
                    else quoted = false;
                } else {
                    cur.append(ch);
                }
            } else if (ch == '"') {
                quoted = true;
            } else if (ch == ',') {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(ch);
            }
        }
        if (quoted) throw new IllegalArgumentException("unterminated quoted field");
        out.add(cur.toString());
        return out;
    }
}
