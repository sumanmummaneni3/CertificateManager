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

import com.codecatalyst.audit.caa.CaaResolution;
import com.codecatalyst.audit.ct.CtIssuance;
import com.codecatalyst.audit.served.AddressObservation;
import com.codecatalyst.audit.served.CertSummary;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Everything one {@code -audit} run found; serialised as {@code audit-<ts>.json} (D1/D8). */
public record AuditReport(RunMeta meta, List<AuditTarget> targets, List<CsvTargetReader.RowError> rowErrors,
                          List<AddressObservation> observations, Map<String, CertSummary> certificates,
                          List<CtDomainResult> ct, List<CaaResolution> caa, List<Finding> findings,
                          List<CheckStatus> coverage) {

    public record RunMeta(String tool, String version, Instant startedAt, Instant finishedAt, String requester,
                          String basis, String csv, String baseline, String resolver, String trustAnchors,
                          int ctCacheTtlHours, boolean ctFetchDer) {}

    /**
     * @param scope          {@code DOMAIN} or {@code HOST_ONLY} (no domain column given, D8)
     * @param currentlyValid issuances valid at run time, the only ones CT-03 judges
     * @param matched        of those, how many an audited endpoint serves
     */
    public record CtDomainResult(String ctDomain, String scope, List<String> hosts, List<CtIssuance> issuances,
                                 Instant fetchedAt, boolean fromCache, List<String> urls, int currentlyValid,
                                 int matched) {}
}
