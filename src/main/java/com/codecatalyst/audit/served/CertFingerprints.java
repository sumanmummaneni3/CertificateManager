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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.List;

/** SHA-256 fingerprints and the chain hash (CHN-02: a hash over the ordered per-cert fingerprints). */
public final class CertFingerprints {

    private CertFingerprints() {}

    public static String sha256(X509Certificate cert) {
        try {
            return sha256(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("certificate cannot be DER-encoded", e);
        }
    }

    public static String sha256(byte[] der) {
        return HexFormat.of().formatHex(digest().digest(der));
    }

    /** SHA-256 over the concatenated raw fingerprints, in served order. */
    public static String chainHash(List<String> orderedSha256Hex) {
        MessageDigest md = digest();
        for (String fp : orderedSha256Hex) {
            md.update(HexFormat.of().parseHex(fp));
        }
        return HexFormat.of().formatHex(md.digest());
    }

    private static MessageDigest digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is mandatory in every JDK", e);
        }
    }
}
