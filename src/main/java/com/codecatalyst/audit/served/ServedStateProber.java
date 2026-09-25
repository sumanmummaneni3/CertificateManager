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

import com.codecatalyst.net.FetchCertificates;
import com.codecatalyst.net.FetchCertificates.ServedHandshake;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;

/**
 * VER-01: resolve every A/AAAA record for a host and handshake with each address, SNI set to the
 * host. One failing address is recorded as unreachable; it never fails the others.
 */
public final class ServedStateProber implements AutoCloseable {

    @FunctionalInterface
    public interface HostResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    @FunctionalInterface
    public interface Handshaker {
        ServedHandshake handshake(InetAddress address, String sniHost, int port) throws Exception;
    }

    private final HostResolver resolver;
    private final Handshaker handshaker;
    private final ExecutorService pool;
    private final Clock clock;

    public ServedStateProber(HostResolver resolver, Handshaker handshaker, int concurrency, Clock clock) {
        this.resolver = resolver;
        this.handshaker = handshaker;
        this.pool = Executors.newFixedThreadPool(Math.max(1, concurrency));
        this.clock = clock;
    }

    public static ServedStateProber live(int concurrency) {
        return new ServedStateProber(InetAddress::getAllByName,
                (addr, sni, port) -> new FetchCertificates(addr, sni, port).fetchHandshake(),
                concurrency, Clock.systemUTC());
    }

    /** @throws UnknownHostException when the host does not resolve at all */
    public List<AddressObservation> probe(String host, int port) throws UnknownHostException, InterruptedException {
        InetAddress[] addresses = resolver.resolve(host);
        List<Future<AddressObservation>> futures = new ArrayList<>();
        for (InetAddress a : Arrays.stream(addresses).distinct().toList()) {
            futures.add(pool.submit(() -> probeOne(host, port, a)));
        }
        List<AddressObservation> out = new ArrayList<>();
        for (Future<AddressObservation> f : futures) {
            try {
                out.add(f.get());
            } catch (ExecutionException e) {
                // probeOne catches everything; this is only reachable on an Error
                throw new IllegalStateException(e.getCause());
            }
        }
        return out;
    }

    private AddressObservation probeOne(String host, int port, InetAddress address) {
        String addr = address.getHostAddress();
        try {
            ServedHandshake h = handshaker.handshake(address, host, port);
            X509Certificate[] chain = h.chain();
            if (chain == null || chain.length == 0) {
                return unreachable(host, port, addr, "handshake completed but the server sent no certificate");
            }
            List<String> fps = Arrays.stream(chain).map(CertFingerprints::sha256).toList();
            return new AddressObservation(host, port, addr, true, fps, fps.get(0),
                    CertFingerprints.chainHash(fps), h.protocol(), h.cipherSuite(), null, clock.instant(), chain);
        } catch (Exception e) {
            Throwable root = e.getCause() != null ? e.getCause() : e;
            return unreachable(host, port, addr, root.getClass().getSimpleName() + ": " + root.getMessage());
        }
    }

    private AddressObservation unreachable(String host, int port, String addr, String error) {
        return new AddressObservation(host, port, addr, false, List.of(), null, null, null, null,
                error, clock.instant(), null);
    }

    @Override
    public void close() {
        pool.shutdownNow();
    }
}
