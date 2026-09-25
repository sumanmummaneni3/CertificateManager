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

import com.codecatalyst.audit.Finding;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/** CAA-02 completeness findings, as amended by D8 (a value that forbids issuance is not a gap). */
public final class CaaEvaluator {

    private CaaEvaluator() {}

    public static List<Finding> evaluate(String ctDomain, CaaResolution r) {
        List<Finding> out = new ArrayList<>();
        String evidence = "caa " + r.queriedName() + " found at " + (r.foundAtName() == null ? "(none)" : r.foundAtName())
                + " via " + r.resolver() + " (" + r.dnssecStatus() + ")";
        if (r.records().isEmpty()) {
            out.add(Finding.of("CAA_ABSENT", ctDomain, r.queriedName(), r.queriedName(),
                    "no CAA record at " + r.queriedName() + " or any parent up to the TLD", evidence, r.observedAt()));
            return out;
        }
        String where = r.queriedName() + (r.queriedName().equals(r.foundAtName()) ? "" : " (inherited from " + r.foundAtName() + ")");

        List<CaaProperty> naming = r.records().stream()
                .filter(CaaProperty::isIssueTag)
                .filter(p -> !p.issuerDomain().isEmpty())
                .toList();
        List<String> noAccount = naming.stream().filter(p -> !p.parameters().containsKey("accounturi"))
                .map(CaaEvaluator::show).toList();
        List<String> noMethod = naming.stream().filter(p -> !p.parameters().containsKey("validationmethods"))
                .map(CaaEvaluator::show).toList();
        if (!noAccount.isEmpty()) {
            out.add(Finding.of("CAA_NO_ACCOUNT_BINDING", ctDomain, r.queriedName(), where,
                    where + ": " + String.join(", ", noAccount) + " has no accounturi", evidence, r.observedAt()));
        }
        if (!noMethod.isEmpty()) {
            out.add(Finding.of("CAA_NO_METHOD_BINDING", ctDomain, r.queriedName(), where,
                    where + ": " + String.join(", ", noMethod) + " has no validationmethods", evidence, r.observedAt()));
        }

        boolean issueNamesCa = naming.stream().anyMatch(p -> p.tag().equalsIgnoreCase("issue"));
        boolean hasIssuewild = r.records().stream().anyMatch(p -> p.tag().toLowerCase(Locale.ROOT).equals("issuewild"));
        if (issueNamesCa && !hasIssuewild) {
            String cas = naming.stream().filter(p -> p.tag().equalsIgnoreCase("issue"))
                    .map(CaaProperty::issuerDomain).distinct().collect(Collectors.joining(", "));
            out.add(Finding.of("CAA_WILDCARD_UNRESTRICTED", ctDomain, r.queriedName(), where,
                    where + ": issue permits " + cas + " and there is no issuewild, so wildcards inherit that permission",
                    evidence, r.observedAt()));
        }
        return out;
    }

    private static String show(CaaProperty p) {
        return p.tag() + " \"" + p.value() + "\"";
    }
}
