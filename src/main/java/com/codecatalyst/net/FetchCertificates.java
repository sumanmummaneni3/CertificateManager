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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


/**
 *
 */
public class FetchCertificates {

   private static final Logger logger = LogManager.getLogger(FetchCertificates.class);
   private static final TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
    };

   private final String host;


    public FetchCertificates(String host){
        this.host = host;
    }


    public X509Certificate fetchCertMetadata() throws CertificateException{
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory factory = sc.getSocketFactory();
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(host, 443), 1500); // Fast 1.5s timeout
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(socket, host, 443, true);
            sslSocket.startHandshake();
            java.security.cert.Certificate[] serverCerts = sslSocket.getSession().getPeerCertificates();
            return (serverCerts.length > 0) ? (X509Certificate) serverCerts[0] : null;
        } catch (KeyManagementException | IOException | NoSuchAlgorithmException e) {
            //System.err.println("Error while fetching certificates: " + e.getMessage());
            logger.error("Error while fetching certificates: ",e);
            throw new CertificateException("Error while fetching certificates: " + e.getMessage());
        }
    }

}
