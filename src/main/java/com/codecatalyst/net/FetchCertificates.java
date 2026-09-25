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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


/**
 * This class fetches the certificate from the provided host and port.
 * If port is not provided it will use 443 as the default port.
 * It return the
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

   // Without a read timeout a server that accepts TCP but never answers the handshake hangs the scan forever
   private static final int HANDSHAKE_TIMEOUT_MS = 10_000;

   /**
    * One handshake's result: the served chain in the order the server sent it (leaf first), and the
    * negotiated protocol and cipher suite (VER-01).
    */
   public record ServedHandshake(X509Certificate[] chain, String protocol, String cipherSuite) {}

   private final String host;
   private int port = -1;
   // When set, connect to exactly this address instead of resolving host (D2: per-address probing)
   private InetAddress address;


    public FetchCertificates(String host){
        this.host = host;
        //Default is 443 port only.
        port = 443;
    }

    public FetchCertificates(String host, int port){
        this.host = host;
        this.port = port;
    }


    /**
     * Connects to {@code address} while sending {@code sniHost} as SNI, so one hostname can be probed
     * on each of its resolved addresses (D2).
     */
    public FetchCertificates(InetAddress address, String sniHost, int port){
        this.host = sniHost;
        this.port = port;
        this.address = address;
    }


    public X509Certificate fetchCertMetadata() throws CertificateException{
        try {
            X509Certificate[] chain = fetchHandshake().chain();
            return (chain.length > 0) ? chain[0] : null;
        } catch (CertificateException e) {
            System.err.println(e.getMessage());
            throw e;
        }
    }

    /**
     * Performs one handshake and returns the full served chain plus protocol and cipher. The
     * trust-all manager is deliberate: the chain is captured as served, whether or not it is valid.
     */
    public ServedHandshake fetchHandshake() throws CertificateException {
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory factory = sc.getSocketFactory();
            Socket socket = new Socket();
            InetSocketAddress remote = (address != null)
                    ? new InetSocketAddress(address, port)
                    : new InetSocketAddress(host, port);
            try {
                socket.connect(remote, 1500); // Fast 1.5s timeout
                socket.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            } catch (IOException e) {
                socket.close();
                throw e;
            }
            try (SSLSocket sslSocket = (SSLSocket) factory.createSocket(socket, host, port, true)) {
                sslSocket.startHandshake();
                SSLSession session = sslSocket.getSession();
                java.security.cert.Certificate[] serverCerts = session.getPeerCertificates();
                X509Certificate[] chain = new X509Certificate[serverCerts.length];
                for (int i = 0; i < serverCerts.length; i++) {
                    chain[i] = (X509Certificate) serverCerts[i];
                }
                return new ServedHandshake(chain, session.getProtocol(), session.getCipherSuite());
            }
        } catch (KeyManagementException | IOException | NoSuchAlgorithmException e) {
            throw new CertificateException("Error while fetching certificates: " + e.getMessage(), e);
        }
    }

}
