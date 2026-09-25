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

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 * One row of the run-wide certificate table, keyed by SHA-256 (CHN-01: each distinct certificate is
 * stored once however many observations served it).
 */
public record CertSummary(String sha256, String subject, String issuer, String serialHex,
                          Instant notBefore, Instant notAfter, String sigAlg, String keyAlg,
                          int keyBits, boolean selfSigned) {

    public static CertSummary of(X509Certificate c) {
        return new CertSummary(CertFingerprints.sha256(c),
                c.getSubjectX500Principal().getName(),
                c.getIssuerX500Principal().getName(),
                c.getSerialNumber().toString(16),
                c.getNotBefore().toInstant(),
                c.getNotAfter().toInstant(),
                c.getSigAlgName(),
                c.getPublicKey().getAlgorithm(),
                keyBits(c.getPublicKey()),
                ChainAnalyzer.isSelfSigned(c));
    }

    /** RSA modulus bits or EC field size; 0 when the algorithm is neither. */
    public static int keyBits(PublicKey key) {
        if (key instanceof RSAPublicKey rsa) return rsa.getModulus().bitLength();
        if (key instanceof ECPublicKey ec) return ec.getParams().getCurve().getField().getFieldSize();
        return 0;
    }
}
