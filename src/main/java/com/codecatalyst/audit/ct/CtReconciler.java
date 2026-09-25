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

import com.codecatalyst.audit.Finding;
import com.codecatalyst.audit.served.CertFingerprints;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

/**
 * CT-02 reconciliation and CT-03 unobserved-issuance detection, as amended by D8.
 */
public final class CtReconciler {

    /** A leaf some audited endpoint served in this run, with where it was seen. */
    public record ServedLeaf(X509Certificate cert, String sha256, String evidence) {}

    /** Fetches one CT entry's DER; only used with {@code --ct-fetch-der}. */
    @FunctionalInterface
    public interface DerFetcher {
        byte[] fetch(long entryId) throws CtLookupException, InterruptedException;
    }

    public record Outcome(List<Finding> findings, int currentlyValid, int matched, List<String> derErrors) {}

    // RFC 6962 precertificate poison extension: a precert's DER can never equal the served certificate's
    private static final String POISON_OID = "1.3.6.1.4.1.11129.2.4.3";

    private CtReconciler() {}

    /** CT-02: one issuance per (issuer, serial), however many log entries carry it. */
    public static List<CtIssuance> reconcile(List<CtEntry> entries) {
        Map<String, List<CtEntry>> groups = new LinkedHashMap<>();
        for (CtEntry e : entries) {
            String key = IssuerNames.key(e.issuerName()) + "|" + serial(e.serialHex());
            groups.computeIfAbsent(key, k -> new ArrayList<>()).add(e);
        }
        List<CtIssuance> out = new ArrayList<>();
        for (List<CtEntry> g : groups.values()) {
            CtEntry first = g.get(0);
            LinkedHashSet<String> names = new LinkedHashSet<>();
            List<Long> ids = new ArrayList<>();
            Instant firstSeen = first.entryTimestamp();
            for (CtEntry e : g) {
                names.addAll(e.names());
                ids.add(e.crtShId());
                if (e.entryTimestamp().isBefore(firstSeen)) firstSeen = e.entryTimestamp();
            }
            Collections.sort(ids);
            out.add(new CtIssuance(first.issuerName(), first.serialHex(), first.commonName(),
                    List.copyOf(names), first.notBefore(), first.notAfter(), firstSeen, List.copyOf(ids)));
        }
        out.sort(Comparator.comparing(CtIssuance::notBefore).reversed());
        return out;
    }

    /**
     * CT-03: every issuance valid at {@code now} must match, on (issuer, serial), a leaf served
     * somewhere in the run. Expired issuances are history, not findings (D8 F2): a one-shot run has
     * no served history to compare them with.
     *
     * @param der null unless {@code --ct-fetch-der}; then matched issuances must also match on SHA-256
     */
    public static Outcome detectUnobserved(String ctDomain, List<CtIssuance> issuances, List<ServedLeaf> served,
                                           Instant now, Instant fetchedAt, DerFetcher der)
            throws InterruptedException {
        List<Finding> findings = new ArrayList<>();
        List<String> derErrors = new ArrayList<>();
        int valid = 0;
        int matched = 0;
        for (CtIssuance iss : issuances) {
            if (!iss.validAt(now)) continue;
            valid++;
            ServedLeaf hit = null;
            for (ServedLeaf s : served) {
                if (s.cert().getSerialNumber().equals(serial(iss.serialHex()))
                        && IssuerNames.same(iss.issuerName(), s.cert().getIssuerX500Principal().getName())) {
                    hit = s;
                    break;
                }
            }
            if (hit == null) {
                findings.add(Finding.of("UNOBSERVED_ISSUANCE", ctDomain, ctDomain,
                        "serial " + iss.serialHex(),
                        "issued by " + iss.issuerName() + " for " + String.join(", ", iss.names())
                                + ", valid " + iss.notBefore() + " to " + iss.notAfter() + ", first logged "
                                + iss.firstSeen() + "; no audited endpoint serves it",
                        iss.evidence(), fetchedAt));
                continue;
            }
            matched++;
            if (der != null) {
                checkFingerprint(ctDomain, iss, hit, der, fetchedAt, findings, derErrors);
            }
        }
        return new Outcome(findings, valid, matched, derErrors);
    }

    private static void checkFingerprint(String ctDomain, CtIssuance iss, ServedLeaf hit, DerFetcher der,
                                         Instant fetchedAt, List<Finding> findings, List<String> derErrors)
            throws InterruptedException {
        boolean sawFinal = false;
        List<String> finalFps = new ArrayList<>();
        for (long id : iss.crtShIds()) {
            byte[] bytes;
            try {
                bytes = der.fetch(id);
            } catch (CtLookupException e) {
                derErrors.add(e.getMessage());
                return; // cannot conclude anything about this issuance
            }
            X509Certificate c;
            try {
                c = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(bytes));
            } catch (Exception e) {
                derErrors.add("crt.sh entry " + id + " is not a parseable certificate: " + e.getMessage());
                return;
            }
            if (c.getExtensionValue(POISON_OID) != null) continue;
            sawFinal = true;
            String fp = CertFingerprints.sha256(c);
            if (fp.equals(hit.sha256())) return;
            finalFps.add(fp);
        }
        if (!sawFinal) {
            derErrors.add("serial " + iss.serialHex() + ": only precertificates are logged, so there is no final "
                    + "certificate to compare by SHA-256");
            return;
        }
        findings.add(Finding.of("CT_FINGERPRINT_MISMATCH", ctDomain, ctDomain, "serial " + iss.serialHex(),
                "served certificate " + hit.sha256() + " matches the CT entry on issuer and serial but the logged "
                        + "certificate is " + String.join(", ", finalFps),
                hit.evidence() + " vs " + iss.evidence(), fetchedAt));
    }

    private static BigInteger serial(String hex) {
        return new BigInteger(hex.replace(":", "").trim(), 16);
    }
}
