package com.codecatalyst.persist;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PersistenceManagerTest {

    private static final String PASSWORD = "passw0rd";
    private PersistenceManager persistenceManager;
    private static final String TEST_KEYSTORE = "keystore.p12";
    @TempDir
    Path tempDir; // Automatically created and deleted by JUnit

    private static File keystoreFile;


    @BeforeEach
    void setUp() {
        // Reset the singleton so each test gets a fresh instance
        PersistenceManager.instance = null;
        persistenceManager = PersistenceManager.getInstance();
        keystoreFile = tempDir.resolve(TEST_KEYSTORE).toFile();
    }

    private static void createCertificate(){
        String[] command = {
                "keytool", "-genkeypair",
                "-alias", "mycert",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-sigalg", "SHA256withRSA",
                "-keystore", keystoreFile.getAbsolutePath(),
                "-storepass", PASSWORD,
                "-keypass", PASSWORD,
                "-validity", "365",
                "-dname", "CN=Test, OU=Test, O=Test, L=Test, S=Test, C=IN",
                "-noprompt" // Skips interactive questions
        };
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.inheritIO(); // Optional: Redirects output to your Java console
        try {
            Process process = pb.start();
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                System.out.println("Certificate generated successfully in myKeystore.jks");
                throw new RuntimeException("Keytool failed with exit code: " + exitCode);
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    @AfterEach
    void tearDown() {
        // Clean up the keystore file created during tests
        File ksFile = new File(TEST_KEYSTORE);
        if (ksFile.exists()) {
            ksFile.delete();
        }
        PersistenceManager.instance = null;
    }

    /**
     * Generates a real self-signed X509Certificate for testing purposes.
     * This avoids the IOException that occurs when PKCS12 tries to encode a Mockito mock.
     */
    private static X509Certificate generateSelfSignedCert() throws Exception {
        createCertificate();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystoreFile.getAbsolutePath())) {
            keyStore.load(fis, PASSWORD.toCharArray());
        }
        // 3. Extract the certificate using the alias
        // Note: getCertificate returns java.security.cert.Certificate, so a cast is needed
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate("Test");

        if (certificate == null) {
            throw new RuntimeException("Alias '" + "Test" + "' not found in keystore");
        }

        return certificate;
    }

    @Test
    @DisplayName("Should retrieve the singleton instance")
    void testGetInstance() {
        PersistenceManager instance1 = PersistenceManager.getInstance();
        PersistenceManager instance2 = PersistenceManager.getInstance();
        assertSame(instance1, instance2, "PersistenceManager should be a singleton");
    }

    @Test
    @DisplayName("Should save and then retrieve a certificate")
    void testSaveAndGetCertificate() throws Exception {
        String alias = "test-alias";
        X509Certificate realCert = generateSelfSignedCert();

        // Save
        persistenceManager.saveCertificate(alias, realCert);

        // Retrieve
        Map<String, X509Certificate> allCerts = persistenceManager.getAllCertificates();

        assertTrue(allCerts.containsKey(alias), "Saved alias should exist in the map");
        assertNotNull(allCerts.get(alias), "Certificate should not be null");
    }

    @Test
    @DisplayName("Should remove a certificate successfully")
    void testRemoveCertificate() throws Exception {
        String alias = "remove-me";
        X509Certificate realCert = generateSelfSignedCert();

        // Ensure it exists
        persistenceManager.saveCertificate(alias, realCert);
        assertTrue(persistenceManager.getAllCertificates().containsKey(alias));

        // Remove
        persistenceManager.removeCertificate(alias);

        // Verify it's gone
        assertFalse(persistenceManager.getAllCertificates().containsKey(alias), "Alias should be removed");
    }

    @Test
    @DisplayName("Should handle certificates chain saving")
    void testSaveCertificateArray() throws Exception {
        String alias = "chain-test";
        X509Certificate cert1 = generateSelfSignedCert();
        X509Certificate cert2 = generateSelfSignedCert();
        X509Certificate[] chain = new X509Certificate[]{cert1, cert2};

        persistenceManager.saveCertificate(alias, chain);

        Map<String, X509Certificate> allCerts = persistenceManager.getAllCertificates();

        // Based on implementation, it saves with suffix "-leaf" and "-inter-1"
        assertTrue(allCerts.keySet().stream().anyMatch(k -> k.startsWith(alias)),
                "At least one alias starting with '" + alias + "' should exist");
        assertTrue(allCerts.containsKey(alias + "-leaf"),
                "Leaf certificate alias should exist");
        assertTrue(allCerts.containsKey(alias + "-inter-1"),
                "Intermediate certificate alias should exist");
    }
}
