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
    public void saveCertificate(String alias, X509Certificate cert) throws CertificateException {

        KeyStore ks = loadKeyStore();

        try {
            // This implicitly updates the cert if the alias already exists
            ks.setCertificateEntry(alias, cert);
        } catch (KeyStoreException e) {
            System.err.println("Error loading keystore: " + e.getMessage());
            throw new CertificateException(e);
        }
        storeKeyStore(ks);
    }

    public void saveCertificate(String alias, X509Certificate[] certs) throws CertificateException {
        KeyStore ks = loadKeyStore();

        String primary = alias + LEAF;
        try {
            ks.setCertificateEntry(primary, certs[0]);
            for (int i = 1; i < certs.length; i++) {
                String intermediateAlias = alias + "-inter-" + i;
                ks.setCertificateEntry(intermediateAlias, certs[i]);
            }
        } catch (KeyStoreException e) {
            System.err.println(e.getMessage());
            throw new CertificateException(e);
        }

        storeKeyStore(ks);
    }

    private void storeKeyStore(KeyStore ks) throws CertificateException {
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password);
        } catch (FileNotFoundException e) {
            System.err.println("File not found: " + keystoreFile.getAbsolutePath());
            throw new CertificateException("Could not fine Keystore file", e);
        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
            throw new CertificateException("Could not save Keystore file", e);
        } catch (IOException e) {
            System.err.println("Could not save Keystore file" + e.getMessage());
            throw new CertificateException("IO Error during save of Keystore file", e);
        }
    }


    /**
     * Retrieves all certificates as a Map (Alias -> Certificate).
     */
    public Map<String, X509Certificate> getAllCertificates() throws CertificateException {
        KeyStore ks = loadKeyStore();
        Map<String, X509Certificate> certMap = new HashMap<>();

        Enumeration<String> aliases = null;
        try {
            aliases = ks.aliases();
        } catch (KeyStoreException e) {
            throw new CertificateException(e);
        }
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            try {
                if (ks.isCertificateEntry(alias)) {
                    certMap.put(alias, (X509Certificate) ks.getCertificate(alias));
                }
            } catch (KeyStoreException e) {
                System.err.println(e.getMessage());
                throw new CertificateException(e);
            }
        }
        return certMap;
    }

    /**
     * Removes the certificate from the keystore that matches the given alias.
     *
     * @param alias used to store the certificate.
     * @throws CertificateException if any error during removal of the given alias.
     */
    public void removeCertificate(String alias) throws CertificateException {
        KeyStore ks = loadKeyStore();
        try {
            if(ks.containsAlias(alias)){
                ks.deleteEntry(alias);
                saveStore(ks);
            }
        } catch (KeyStoreException e) {
            System.err.println("Could not remove Keystore entry: " + alias);
            throw new CertificateException(e);
        }
    }

    // --- Private Helper to Load File ---
    private KeyStore loadKeyStore() throws CertificateException {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(KEYSTORE_TYPE);
        } catch (KeyStoreException e) {
            System.err.println("Unable to load keystore: " + e.getMessage());
            throw new CertificateException("Failed to load Keystore of type - "+KEYSTORE_TYPE, e);
        }


        if (keystoreFile.exists()) {
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                ks.load(fis, password);
            } catch (FileNotFoundException e) {
                System.err.println("Unable to load keystore: " + e.getMessage());
                throw new CertificateException("Could not find Keystore file - "+keystoreFile.getAbsolutePath(), e);
            } catch (IOException | NoSuchAlgorithmException e) {
                System.err.println("Unable to load keystore: " + e.getMessage());
                throw new CertificateException("IO Error loading  Keystore - "+keystoreFile.getAbsolutePath(), e);
            }
        } else {
            // Initialize a new empty keystore if file doesn't exist
            try {
                ks.load(null, password);
            } catch (IOException | NoSuchAlgorithmException e) {
                System.err.println("Unable to load keystore: " + e.getMessage());
                throw new CertificateException(e);
            }
        }
        return ks;
    }

    private void saveStore(KeyStore ks) throws CertificateException{
        try(FileOutputStream fos = new FileOutputStream(keystoreFile)){
            ks.store(fos, password);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException e) {
            System.err.println("Unable to store Keystore - "+keystoreFile.getAbsolutePath());
            throw new CertificateException(e);
        }
    }


}
