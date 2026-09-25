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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * One audit finding (D1, amended by D8). Why-it-matters and remediation text are not stored per
 * finding: they come from {@link FindingCatalog} by type, so every finding of a type says the same
 * thing and no call site can forget them.
 *
 * @param type       finding type, e.g. {@code NODE_DIVERGENCE}
 * @param severity   severity, normally {@link FindingCatalog#severity(String)}
 * @param ctDomain   the CT domain this finding belongs to (row's {@code domain}, or its host)
 * @param host       the host the finding is about, or the CT domain for domain-level findings
 * @param subject    the precise thing observed, e.g. {@code host:443@192.0.2.1 position 1}
 * @param detail     one-sentence description of what was observed
 * @param evidence   where in the JSON export, or which URL, the evidence lives
 * @param observedAt when the evidence was captured (a cached CT answer carries its fetch time)
 */
public record Finding(String type, Severity severity, String ctDomain, String host, String subject,
                      String detail, String evidence, Instant observedAt) {

    public static Finding of(String type, String ctDomain, String host, String subject,
                             String detail, String evidence, Instant observedAt) {
        return new Finding(type, FindingCatalog.severity(type), ctDomain, host, subject, detail,
                evidence, observedAt);
    }

    @JsonProperty("why")
    public String why() {
        return FindingCatalog.why(type);
    }

    @JsonProperty("remediation")
    public String remediation() {
        return FindingCatalog.remediation(type);
    }
}
