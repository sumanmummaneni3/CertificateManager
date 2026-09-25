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
 * The single place each finding type's default severity (requirements ALR-02), why-it-matters text
 * and remediation text live (D8, RPT-01: "every finding states what was observed, why it matters,
 * and the specific remediation").
 */
public final class FindingCatalog {

    private record Entry(Severity severity, String why, String remediation) {}

    private static final String MANDATE =
            " CAs must honour accounturi and validationmethods from March 2027 (CA/B Forum SC-098v2).";

    private static final Map<String, Entry> ENTRIES = Map.ofEntries(
            Map.entry("NODE_DIVERGENCE", new Entry(Severity.HIGH,
                    "Clients get a different certificate or chain depending on which address they reach, so a renewal that looks deployed is only deployed on some nodes.",
                    "Deploy the current certificate and chain to every node behind this name and reload each one; re-run the audit to confirm all addresses match.")),
            Map.entry("CHAIN_CHANGED", new Entry(Severity.HIGH,
                    "The intermediate chain changed while the leaf did not; clients that pin or cache the old path (often Java) can break without any renewal having happened.",
                    "Confirm the chain change was intended (e.g. a CA cross-sign change); if not, restore the previous bundle and find what pushed the new one.")),
            Map.entry("EXPIRED_SERVED_CERT", new Entry(Severity.CRITICAL,
                    "The certificate this endpoint serves has expired; every validating client refuses the connection.",
                    "Install a renewed certificate on this endpoint and reload the service.")),
            Map.entry("EXPIRED_IN_CHAIN", new Entry(Severity.MEDIUM,
                    "An expired certificate is being served in the chain; modern clients usually route around it but older clients may build the path through it and fail.",
                    "Remove the expired certificate from the served bundle (commonly an old cross-sign) and serve only the current intermediates.")),
            Map.entry("ROOT_INCLUDED", new Entry(Severity.MEDIUM,
                    "The root certificate is being sent; clients ignore it, it only adds handshake size, and it can mask a trust-store problem during testing.",
                    "Remove the root from the served bundle; serve leaf plus intermediates only.")),
            Map.entry("WRONG_ORDER", new Entry(Severity.MEDIUM,
                    "The served certificates are out of order; strict clients that expect each certificate to certify the one before it can fail.",
                    "Reorder the bundle: leaf first, then each issuer in turn.")),
            Map.entry("MISSING_INTERMEDIATE", new Entry(Severity.MEDIUM,
                    "The served chain does not reach a public trust anchor and names no issuer URL, so no client can complete it unless it already holds the intermediate (or this is a private PKI the audit does not know).",
                    "Serve the issuing intermediate(s) with the leaf; if this is a private PKI, confirm its root is distributed to every client.")),
            Map.entry("AIA_ONLY_COMPLETION", new Entry(Severity.MEDIUM,
                    "The intermediate is not served; browsers fetch it from the AIA URL, but most non-browser clients (Java, curl, many appliances and APIs) do not and will fail.",
                    "Serve the intermediate named by the AIA URL together with the leaf.")),
            Map.entry("WEAK_SIGNATURE", new Entry(Severity.MEDIUM,
                    "A certificate in the chain is signed with MD5 or SHA-1, which current clients reject.",
                    "Reissue with a SHA-256 (or stronger) signature, or replace the intermediate with its current version.")),
            Map.entry("WEAK_KEY", new Entry(Severity.MEDIUM,
                    "A certificate in the chain uses a key below current minimums (RSA < 2048 bits or EC < 224 bits).",
                    "Reissue with an RSA 2048+ or P-256+ key.")),
            Map.entry("UNOBSERVED_ISSUANCE", new Entry(Severity.MEDIUM,
                    "A currently valid, publicly trusted certificate exists for this domain that none of the audited endpoints serve; someone or something obtained it outside what was audited.",
                    "Identify who requested it (issuer, SANs and CT entry are in the finding); if nobody owns it, revoke it through the issuing CA and tighten CAA.")),
            Map.entry("CT_FINGERPRINT_MISMATCH", new Entry(Severity.HIGH,
                    "A served certificate matches a CT entry on issuer and serial but not on content; that should be impossible for a correctly issued certificate.",
                    "Treat as suspect: compare the served certificate with the CT entry by hand and contact the issuing CA.")),
            Map.entry("CAA_ABSENT", new Entry(Severity.LOW,
                    "No CAA record exists anywhere above this name, so any publicly trusted CA may issue for it.",
                    "Publish CAA issue/issuewild records naming only the CAs you use, with accounturi and validationmethods." + MANDATE)),
            Map.entry("CAA_NO_ACCOUNT_BINDING", new Entry(Severity.MEDIUM,
                    "CAA names a CA but no accounturi, so any party able to complete a challenge at this CA can obtain a certificate, not only your account.",
                    "Add accounturi=<your ACME account URL> to each issue/issuewild value." + MANDATE)),
            Map.entry("CAA_NO_METHOD_BINDING", new Entry(Severity.LOW,
                    "CAA names a CA but no validationmethods, so any party able to complete a DNS-01 challenge at this CA can obtain a certificate (for example a DNS provider).",
                    "Add validationmethods=<the methods you use, e.g. http-01> to each issue/issuewild value." + MANDATE)),
            Map.entry("CAA_WILDCARD_UNRESTRICTED", new Entry(Severity.LOW,
                    "CAA has issue but no issuewild, so wildcard certificates are permitted by inheritance from issue.",
                    "Add issuewild \";\" if you never use wildcards, or an explicit issuewild naming the CA and account that should issue them."))
    );

    private FindingCatalog() {}

    public static Severity severity(String type) {
        return entry(type).severity();
    }

    public static String why(String type) {
        return entry(type).why();
    }

    public static String remediation(String type) {
        return entry(type).remediation();
    }

    public static boolean isKnown(String type) {
        return ENTRIES.containsKey(type);
    }

    private static Entry entry(String type) {
        Entry e = ENTRIES.get(type);
        if (e == null) {
            throw new IllegalArgumentException("Finding type not in FindingCatalog: " + type);
        }
        return e;
    }
}
