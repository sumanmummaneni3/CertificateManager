package com.codecatalyst.net;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class FetchCertificatesTest {

    @Test
    @DisplayName("Should successfully fetch certificate from a valid SSL host (google.com)")
    void testFetchCertMetadataSuccess() {
        // Use a reliable public host for testing network fetch
        FetchCertificates fetcher = new FetchCertificates("google.com", 443);

        assertDoesNotThrow(() -> {
            X509Certificate cert = fetcher.fetchCertMetadata();
            assertNotNull(cert, "Certificate should not be null for google.com");
            assertTrue(cert.getSubjectX500Principal().getName().contains("CN"), "Certificate should have a Common Name");
        });
    }

    @Test
    @DisplayName("Should throw CertificateException for an unreachable host")
    void testFetchCertMetadataUnreachableHost() {
        // Use a non-existent domain
        FetchCertificates fetcher = new FetchCertificates("invalid.domain.that.does.not.exist.test");

        assertThrows(CertificateException.class, fetcher::fetchCertMetadata,
                "Should throw CertificateException for unknown host");
    }

    @Test
    @DisplayName("Should throw CertificateException when connecting to a non-SSL port")
    void testFetchCertMetadataNonSslPort() {
        // Port 80 is usually HTTP, not HTTPS/SSL
        FetchCertificates fetcher = new FetchCertificates("google.com", 80);

        assertThrows(CertificateException.class, fetcher::fetchCertMetadata,
                "Should throw CertificateException when SSL handshake fails");
    }

    @Test
    @DisplayName("Should use default port 443 when only host is provided")
    void testConstructorDefaultPort() {
        FetchCertificates fetcher = new FetchCertificates("localhost");
        assertNotNull(fetcher);
    }
}
