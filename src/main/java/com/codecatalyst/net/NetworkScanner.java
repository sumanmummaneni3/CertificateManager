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
package com.codecatalyst.net;

import com.codecatalyst.persist.PersistenceManager;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 *
 */
public class NetworkScanner {
    // Thread pool for fast scanning
    private final ExecutorService executor = Executors.newFixedThreadPool(20);

    public NetworkScanner(){}

    public void scanAndStore(List<String> targets, Set<Integer> ports) {
        for (String target : targets) {
            for (Integer port : ports) {
                executor.submit(() -> {
                    try (Socket socket = new Socket()) {
                        socket.connect(new InetSocketAddress(target, port), 2000);
                        fetchAndStoreCert(target, port);
                    } catch (CertificateException | IOException e) {
                        System.err.println(e.getMessage());
                    }
                });
            }
        }
        executor.shutdown();
    }

    private void fetchAndStoreCert(String host, int port) throws CertificateException {
        X509Certificate cert = new FetchCertificates(host, port).fetchCertMetadata();
        PersistenceManager.getInstance().saveCertificate(host, cert);
    }
}
