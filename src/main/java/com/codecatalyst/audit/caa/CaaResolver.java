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

import java.io.IOException;
import java.time.Clock;
import java.util.List;

/**
 * RFC 8659 §3 tree-climbing (D8 F7): query the name, then each parent, down to and including the TLD,
 * and take the first non-empty CAA RRset. NXDOMAIN and an empty answer continue the climb; any other
 * response code or a transport failure stops it with the failure as received, because an unknown
 * answer must never be reported as "no CAA".
 */
public class CaaResolver {

    private final CaaQuerier querier;
    private final String resolverLabel;
    private final Clock clock;

    public CaaResolver(CaaQuerier querier, String resolverLabel, Clock clock) {
        this.querier = querier;
        this.resolverLabel = resolverLabel;
        this.clock = clock;
    }

    public CaaResolution resolve(String name) throws CaaLookupException {
        String n = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        String[] labels = n.split("\\.");
        boolean allAd = true;
        for (int i = 0; i < labels.length; i++) {
            String candidate = String.join(".", List.of(labels).subList(i, labels.length));
            CaaAnswer a;
            try {
                a = querier.query(candidate);
            } catch (IOException e) {
                throw new CaaLookupException("CAA query for " + candidate + " via " + resolverLabel + " failed: "
                        + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            if (a.rcode() != CaaAnswer.NOERROR && a.rcode() != CaaAnswer.NXDOMAIN) {
                throw new CaaLookupException("CAA query for " + candidate + " via " + resolverLabel
                        + " returned " + a.rcodeName());
            }
            allAd &= a.ad();
            if (a.rcode() == CaaAnswer.NOERROR && !a.records().isEmpty()) {
                return new CaaResolution(n, candidate, List.copyOf(a.records()), resolverLabel,
                        a.ad() ? "VALIDATED_BY_RESOLVER" : "UNVALIDATED", clock.instant());
            }
        }
        // Absence is only as trustworthy as every negative answer in the climb.
        return new CaaResolution(n, null, List.of(), resolverLabel,
                allAd ? "VALIDATED_BY_RESOLVER" : "UNVALIDATED", clock.instant());
    }
}
