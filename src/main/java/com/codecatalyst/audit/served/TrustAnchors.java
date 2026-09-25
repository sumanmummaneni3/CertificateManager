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

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Public trust anchors for CHN-03's "does the served chain reach an anchor?" question (D8 F1).
 * This is not path validation: it only answers whether a certificate is signed by an anchor, which
 * is all that is needed to tell a correctly served chain (root omitted) from a missing intermediate.
 */
public final class TrustAnchors {

    private final List<X509Certificate> anchors;
    private final String source;

    public TrustAnchors(List<X509Certificate> anchors, String source) {
        this.anchors = List.copyOf(anchors);
        this.source = source;
    }

    /** The JDK's default trust store (cacerts), the same one the JVM's own clients use. */
    public static TrustAnchors jdkDefault() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            for (var tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager x) {
                    return new TrustAnchors(List.of(x.getAcceptedIssuers()),
                            "JDK default trust store (" + System.getProperty("java.version") + ")");
                }
            }
            throw new IllegalStateException("JDK exposes no X509TrustManager");
        } catch (Exception e) {
            throw new IllegalStateException("Cannot load the JDK default trust store: " + e.getMessage(), e);
        }
    }

    /** True when an anchor with the certificate's issuer DN verifies its signature. */
    public boolean signs(X509Certificate cert) {
        for (X509Certificate anchor : anchors) {
            if (!anchor.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) continue;
            try {
                cert.verify(anchor.getPublicKey());
                return true;
            } catch (Exception ignored) {
                // same DN, different key (e.g. a re-keyed root): keep looking
            }
        }
        return false;
    }

    /** True when the certificate is an anchor itself: same subject and same public key. */
    public boolean contains(X509Certificate cert) {
        for (X509Certificate anchor : anchors) {
            if (anchor.getSubjectX500Principal().equals(cert.getSubjectX500Principal())
                    && anchor.getPublicKey().equals(cert.getPublicKey())) {
                return true;
            }
        }
        return false;
    }

    public int size() {
        return anchors.size();
    }

    public String source() {
        return source;
    }
}
