package com.codecatalyst.audit.served;

import com.codecatalyst.audit.TestCerts;
import com.codecatalyst.net.FetchCertificates.ServedHandshake;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.ConnectException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.junit.jupiter.api.Assertions.*;

class ServedStateProberTest {

    private static final TestCerts.Chain C = TestCerts.chain();
    private static final Clock CLOCK = Clock.fixed(TestCerts.NOW, ZoneOffset.UTC);

    @Test
    @DisplayName("Every resolved address (IPv4 and IPv6) is probed with SNI set to the hostname; one failure does not fail the others")
    void perAddressObservations() throws Exception {
        InetAddress a = InetAddress.getByName("192.0.2.1");
        InetAddress b = InetAddress.getByName("192.0.2.2");
        InetAddress v6 = InetAddress.getByName("2001:db8::1");
        ConcurrentLinkedQueue<String> sni = new ConcurrentLinkedQueue<>();
        try (ServedStateProber p = new ServedStateProber(h -> new InetAddress[]{a, b, v6}, (addr, host, port) -> {
            sni.add(host);
            if (addr.equals(b)) throw new CertificateException("wrapped", new ConnectException("Connection refused"));
            return new ServedHandshake(new java.security.cert.X509Certificate[]{C.leaf(), C.inter()}, "TLSv1.3", "TLS_AES_128_GCM_SHA256");
        }, 2, CLOCK)) {
            List<AddressObservation> obs = p.probe("www.example.com", 443);
            assertEquals(3, obs.size());
            assertEquals(List.of("www.example.com", "www.example.com", "www.example.com"), List.copyOf(sni));
            AddressObservation down = obs.stream().filter(o -> o.address().equals("192.0.2.2")).findFirst().orElseThrow();
            assertFalse(down.reachable());
            assertEquals("ConnectException: Connection refused", down.error());
            AddressObservation up = obs.stream().filter(o -> o.address().equals("192.0.2.1")).findFirst().orElseThrow();
            assertTrue(up.reachable());
            assertEquals(2, up.chainSha256().size());
            assertEquals(CertFingerprints.sha256(C.leaf()), up.leafSha256());
            assertEquals("TLSv1.3", up.protocol());
            assertTrue(obs.stream().anyMatch(o -> o.address().contains(":") && o.reachable()), "IPv6 address probed");
        }
    }

    @Test
    @DisplayName("A name that does not resolve surfaces UnknownHostException to the caller")
    void unresolvable() {
        try (ServedStateProber p = new ServedStateProber(h -> { throw new UnknownHostException(h); },
                (addr, host, port) -> null, 1, CLOCK)) {
            assertThrows(UnknownHostException.class, () -> p.probe("nope.invalid", 443));
        }
    }
}
