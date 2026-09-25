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

import java.time.Instant;
import java.util.List;

/**
 * Effective CAA for one name (CAA-01).
 *
 * @param foundAtName  the owner name the RRset was found at, or null when none exists up to the TLD
 * @param resolver     the recursive resolver queried
 * @param dnssecStatus {@code VALIDATED_BY_RESOLVER} when the resolver set AD, else {@code UNVALIDATED};
 *                     relayed from the resolver, not validated independently (backlog D6)
 */
public record CaaResolution(String queriedName, String foundAtName, List<CaaProperty> records,
                            String resolver, String dnssecStatus, Instant observedAt) {}
