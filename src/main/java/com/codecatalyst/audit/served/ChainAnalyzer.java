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

package com.codecatalyst.audit.served;

import com.codecatalyst.audit.Finding;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Pure served-state and chain checks (VER-02, CHN-02, CHN-03), as amended by D8. No network I/O.
 */
public final class ChainAnalyzer {

    private static final String AIA_OID = "1.3.6.1.5.5.7.1.1";
    // DER of OID 1.3.6.1.5.5.7.48.2 (id-ad-caIssuers)
    private static final byte[] CA_ISSUERS_OID = {0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02};

    private ChainAnalyzer() {}

    /**
     * VER-02: reachable addresses behind one host:port serving different leaves or chains. Names
     * every address and its fingerprints; which node is stale is for the operator to judge.
     */
    public static Optional<Finding> detectNodeDivergence(String ctDomain, List<AddressObservation> obs) {
        List<AddressObservation> reachable = obs.stream().filter(AddressObservation::reachable).toList();
        Set<String> variants = reachable.stream()
                .map(o -> o.leafSha256() + "/" + o.chainHash())
                .collect(Collectors.toCollection(TreeSet::new));
        if (variants.size() < 2) return Optional.empty();
        AddressObservation first = reachable.get(0);
        String detail = reachable.stream()
                .map(o -> o.address() + " leaf " + shortFp(o.leafSha256()) + " chain " + shortFp(o.chainHash()))
                .collect(Collectors.joining("; ",
                        first.host() + ":" + first.port() + " serves " + variants.size()
                                + " different leaf/chain combinations: ", ""));
        String evidence = reachable.stream().map(AddressObservation::evidence).collect(Collectors.joining(", "));
        Instant at = reachable.stream().map(AddressObservation::observedAt).max(Comparator.naturalOrder()).orElse(null);
        return Optional.of(Finding.of("NODE_DIVERGENCE", ctDomain, first.host(),
                first.host() + ":" + first.port(), detail, evidence, at));
    }

    /** CHN-03 defects for one reachable observation, judged at {@code now}. */
    public static List<Finding> detectChainDefects(String ctDomain, AddressObservation obs,
                                                   TrustAnchors anchors, Instant now) {
        List<Finding> out = new ArrayList<>();
        X509Certificate[] c = obs.chain();
        if (!obs.reachable() || c == null || c.length == 0) return out;
        Date nowDate = Date.from(now);

        for (int i = 0; i < c.length; i++) {
            if (nowDate.after(c[i].getNotAfter())) {
                String type = (i == 0) ? "EXPIRED_SERVED_CERT" : "EXPIRED_IN_CHAIN";
                out.add(finding(type, ctDomain, obs, i, c[i],
                        "position " + i + " (" + cn(c[i]) + ") expired " + c[i].getNotAfter().toInstant()));
            }
        }

        if (c.length > 1 && isSelfSigned(c[c.length - 1])) {
            X509Certificate root = c[c.length - 1];
            out.add(finding("ROOT_INCLUDED", ctDomain, obs, c.length - 1, root,
                    "the served chain ends with the self-signed root " + cn(root)));
        }

        for (int i = 0; i + 1 < c.length; i++) {
            if (!c[i].getIssuerX500Principal().equals(c[i + 1].getSubjectX500Principal())) {
                final int at = i;
                boolean issuerServedElsewhere = false;
                for (int j = 0; j < c.length; j++) {
                    if (j != at && j != at + 1 && c[j].getSubjectX500Principal().equals(c[at].getIssuerX500Principal())) {
                        issuerServedElsewhere = true;
                        break;
                    }
                }
                if (issuerServedElsewhere) {
                    out.add(finding("WRONG_ORDER", ctDomain, obs, i + 1, c[i + 1],
                            "position " + (i + 1) + " (" + cn(c[i + 1]) + ") does not certify position " + i
                                    + " (" + cn(c[i]) + "); its issuer is served elsewhere in the chain"));
                    break;
                }
            }
        }

        // Walk the served set from the leaf, whatever order it was sent in, stopping at the first
        // certificate that is, or is signed by, a trust anchor. Walking past an anchor into a cross-sign
        // whose own issuer this trust store lacks would report a correct chain as broken (D8 F13).
        X509Certificate top = walkServedPath(c, anchors);
        if (!isSelfSigned(top) && !anchors.contains(top) && !anchors.signs(top)) {
            Optional<String> aia = caIssuersUrl(top);
            if (aia.isPresent()) {
                out.add(finding("AIA_ONLY_COMPLETION", ctDomain, obs, indexOf(c, top), top,
                        "the served chain stops at " + cn(top) + "; its issuer is not served and is only reachable via AIA "
                                + aia.get()));
            } else {
                out.add(finding("MISSING_INTERMEDIATE", ctDomain, obs, indexOf(c, top), top,
                        "the served chain stops at " + cn(top) + ", whose issuer (" + top.getIssuerX500Principal().getName()
                                + ") is neither served nor a public trust anchor, and it names no AIA issuer URL"));
            }
        }

        for (int i = 0; i < c.length; i++) {
            if (isSelfSigned(c[i])) continue; // nobody verifies a root's own signature
            String alg = c[i].getSigAlgName().toUpperCase(Locale.ROOT).replace("-", "");
            if (alg.contains("MD5") || alg.contains("SHA1")) {
                out.add(finding("WEAK_SIGNATURE", ctDomain, obs, i, c[i],
                        "position " + i + " (" + cn(c[i]) + ") is signed with " + c[i].getSigAlgName()));
            }
        }

        for (int i = 0; i < c.length; i++) {
            String keyAlg = c[i].getPublicKey().getAlgorithm();
            int bits = CertSummary.keyBits(c[i].getPublicKey());
            boolean weak = ("RSA".equals(keyAlg) && bits < 2048) || ("EC".equals(keyAlg) && bits < 224);
            if (weak) {
                out.add(finding("WEAK_KEY", ctDomain, obs, i, c[i],
                        "position " + i + " (" + cn(c[i]) + ") has a " + bits + "-bit " + keyAlg + " key"));
            }
        }
        return out;
    }

    /**
     * CHN-02 (D8): compare an observation with every baseline observation for the same host:port
     * that served the same leaf. Raises only when none of them had this chain hash. An empty list
     * of candidates means "not comparable", which the caller records as coverage, not as a pass.
     */
    public static Optional<Finding> detectChainChanged(String ctDomain, AddressObservation current,
                                                       List<BaselineObservation> sameLeafBaseline,
                                                       Map<String, String> subjectBySha) {
        if (!current.reachable() || sameLeafBaseline.isEmpty()) return Optional.empty();
        for (BaselineObservation b : sameLeafBaseline) {
            if (b.chainHash().equals(current.chainHash())) return Optional.empty();
        }
        BaselineObservation prior = sameLeafBaseline.get(0);
        List<String> removed = new ArrayList<>(prior.chainSha256());
        removed.removeAll(current.chainSha256());
        List<String> added = new ArrayList<>(current.chainSha256());
        added.removeAll(prior.chainSha256());
        String detail = "chain changed with the same leaf since " + prior.observedAt() + " (baseline address "
                + prior.address() + "); removed: " + describe(removed, subjectBySha)
                + "; added: " + describe(added, subjectBySha)
                + (removed.isEmpty() && added.isEmpty() ? "; same certificates, different order" : "");
        return Optional.of(Finding.of("CHAIN_CHANGED", ctDomain, current.host(), current.subject(), detail,
                current.evidence() + " vs baseline " + prior.host() + ":" + prior.port() + "@" + prior.address(),
                current.observedAt()));
    }

    /** Subject equals issuer and the certificate verifies with its own key. */
    public static boolean isSelfSigned(X509Certificate c) {
        if (!c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) return false;
        try {
            c.verify(c.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** The URL of the first AIA caIssuers entry, if the certificate has one. */
    public static Optional<String> caIssuersUrl(X509Certificate c) {
        byte[] ext = c.getExtensionValue(AIA_OID);
        if (ext == null) return Optional.empty();
        // Find id-ad-caIssuers, then the uniformResourceIdentifier ([6] IMPLICIT IA5String, tag 0x86) after it.
        for (int i = 0; i + CA_ISSUERS_OID.length + 2 <= ext.length; i++) {
            if (!Arrays.equals(ext, i, i + CA_ISSUERS_OID.length, CA_ISSUERS_OID, 0, CA_ISSUERS_OID.length)) continue;
            int p = i + CA_ISSUERS_OID.length;
            if ((ext[p] & 0xFF) != 0x86) continue;
            int len = ext[p + 1] & 0xFF;
            int start = p + 2;
            if ((len & 0x80) != 0) {
                int n = len & 0x7F;
                len = 0;
                for (int k = 0; k < n; k++) len = (len << 8) | (ext[start + k] & 0xFF);
                start += n;
            }
            if (start + len > ext.length) return Optional.empty();
            return Optional.of(new String(ext, start, len, StandardCharsets.US_ASCII));
        }
        return Optional.empty();
    }

    private static X509Certificate walkServedPath(X509Certificate[] c, TrustAnchors anchors) {
        X509Certificate cur = c[0];
        Set<X509Certificate> used = new HashSet<>();
        used.add(cur);
        while (!isSelfSigned(cur) && !anchors.contains(cur) && !anchors.signs(cur)) {
            X509Certificate next = null;
            for (X509Certificate cand : c) {
                if (used.contains(cand) || !cand.getSubjectX500Principal().equals(cur.getIssuerX500Principal())) continue;
                try {
                    cur.verify(cand.getPublicKey());
                    next = cand;
                    break;
                } catch (Exception ignored) {
                    // same DN, not the signer
                }
            }
            if (next == null) break;
            used.add(next);
            cur = next;
        }
        return cur;
    }

    private static int indexOf(X509Certificate[] c, X509Certificate x) {
        for (int i = 0; i < c.length; i++) if (c[i] == x) return i;
        return -1;
    }

    private static Finding finding(String type, String ctDomain, AddressObservation obs, int pos,
                                   X509Certificate cert, String detail) {
        return Finding.of(type, ctDomain, obs.host(), obs.subject() + " position " + pos,
                obs.subject() + ": " + detail, obs.evidence() + " cert " + CertFingerprints.sha256(cert),
                obs.observedAt());
    }

    private static String describe(List<String> fps, Map<String, String> subjectBySha) {
        if (fps.isEmpty()) return "none";
        return fps.stream()
                .map(fp -> subjectBySha.getOrDefault(fp, "(subject unknown)") + " [" + fp + "]")
                .collect(Collectors.joining(", "));
    }

    static String cn(X509Certificate c) {
        String dn = c.getSubjectX500Principal().getName();
        for (String part : dn.split(",")) {
            if (part.trim().startsWith("CN=")) return part.trim().substring(3);
        }
        return dn;
    }

    private static String shortFp(String fp) {
        return fp == null ? "-" : fp.substring(0, Math.min(16, fp.length()));
    }
}
