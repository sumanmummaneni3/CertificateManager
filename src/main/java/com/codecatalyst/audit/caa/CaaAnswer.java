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

import java.util.List;

/**
 * One CAA query's answer.
 *
 * @param rcode    DNS response code
 * @param rcodeName its mnemonic, e.g. {@code SERVFAIL}
 * @param ad       the response header's Authenticated Data bit
 */
public record CaaAnswer(int rcode, String rcodeName, boolean ad, List<CaaProperty> records) {
    public static final int NOERROR = 0;
    public static final int NXDOMAIN = 3;
}
