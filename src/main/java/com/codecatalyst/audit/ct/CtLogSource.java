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

/** A CT search provider (CT-01). crt.sh is the only one (D8); this seam is what makes a swap cheap. */
public interface CtLogSource {

    /** Every logged entry for {@code domain} and its subdomains. */
    CtFetchResult fetch(String domain) throws CtLookupException, InterruptedException;

    /** The DER of one entry, for the opt-in SHA-256 match (D8). */
    byte[] fetchDer(long entryId) throws CtLookupException, InterruptedException;
}
