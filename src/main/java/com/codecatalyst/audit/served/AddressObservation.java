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

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * What one address served for one host:port at one time (VER-01). An unreachable address is
 * recorded with {@code reachable = false} and its error, not dropped.
 *
 * @param chainSha256 ordered fingerprints of the served chain (CHN-01)
 * @param chain       the certificates themselves; kept out of the JSON, which holds them once in
 *                    the certificate table instead
 */
public record AddressObservation(String host, int port, String address, boolean reachable,
                                 List<String> chainSha256, String leafSha256, String chainHash,
                                 String protocol, String cipher, String error, Instant observedAt,
                                 @JsonIgnore X509Certificate[] chain) {

    public String subject() {
        return host + ":" + port + "@" + address;
    }

    public String evidence() {
        return "observation " + subject();
    }
}
