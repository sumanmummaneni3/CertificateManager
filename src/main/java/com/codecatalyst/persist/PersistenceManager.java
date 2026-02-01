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

package com.codecatalyst.persist;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import static com.codecatalyst.CertConstants.*;

public class PersistenceManager {

    public static PersistenceManager instance;

    private final File keystoreFile;
    private final char[] password;

    private PersistenceManager(){
        this.keystoreFile = new File(KEYSTORE_FILE);
        this.password = PASSWORD;
    }

    public static PersistenceManager getInstance() {
        if(instance == null){
            instance = new PersistenceManager();
        }
        return instance;
    }

    /**
     * Saves a certificate to the KeyStore file.
     * @param alias The unique identifier (e.g., hostname or IP)
     * @param cert The certificate object to store
     */
    public void saveCertificate(String alias, X509Certificate cert) throws Exception {
        KeyStore ks = loadKeyStore();

        // This implicitly updates the cert if the alias already exists
        ks.setCertificateEntry(alias, cert);

        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password);
        }
    }

    /**
     * Retrieves all certificates as a Map (Alias -> Certificate).
     */
    public Map<String, X509Certificate> getAllCertificates() throws Exception {
        KeyStore ks = loadKeyStore();
        Map<String, X509Certificate> certMap = new HashMap<>();

        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isCertificateEntry(alias)) {
                certMap.put(alias, (X509Certificate) ks.getCertificate(alias));
            }
        }
        return certMap;
    }

    /**
     * Removes the certificate from the keystore that matches the given alias.
     *
     * @param alias used to store the certificate.
     * @throws Exception if any error during removal of the given alias.
     */
    public void removeCertificate(String alias) throws Exception {
        KeyStore ks = loadKeyStore();
        if(ks.containsAlias(alias)){
            ks.deleteEntry(alias);
            saveStore(ks);
        }
    }

    // --- Private Helper to Load File ---
    private KeyStore loadKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);

        if (keystoreFile.exists()) {
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                ks.load(fis, password);
            }
        } else {
            // Initialize a new empty keystore if file doesn't exist
            ks.load(null, password);
        }
        return ks;
    }

    private void saveStore(KeyStore ks) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        try(FileOutputStream fos = new FileOutputStream(keystoreFile)){
            ks.store(fos, password);
        }
    }


}
