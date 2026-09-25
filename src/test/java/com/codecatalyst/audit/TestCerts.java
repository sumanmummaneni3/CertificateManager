package com.codecatalyst.audit;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/** Throwaway X.509 certificates for audit-kit tests. Keys are generated once per JVM; RSA is slow. */
public final class TestCerts {

    public static final Instant NOW = Instant.parse("2026-09-25T12:00:00Z");
    public static final KeyPair ROOT_KEY = rsa(2048);
    public static final KeyPair INTER_KEY = rsa(2048);
    public static final KeyPair INTER2_KEY = rsa(2048);
    public static final KeyPair LEAF_KEY = rsa(2048);
    public static final KeyPair WEAK_KEY = rsa(1024);

    private static final AtomicLong SERIALS = new AtomicLong(1000);

    private TestCerts() {}

    public static KeyPair rsa(int bits) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(bits);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A fluent spec for one certificate. */
    public static Spec cert(String subjectCn) {
        return new Spec(subjectCn);
    }

    public static final class Spec {
        private final String subject;
        private String issuer;
        private KeyPair keys = LEAF_KEY;
        private PrivateKey signer;
        private boolean ca;
        private Instant notBefore = NOW.minus(Duration.ofDays(30));
        private Instant notAfter = NOW.plus(Duration.ofDays(60));
        private String sigAlg = "SHA256withRSA";
        private String aia;
        private BigInteger serial = BigInteger.valueOf(SERIALS.incrementAndGet());

        private Spec(String cn) {
            this.subject = "CN=" + cn + ",O=Test,C=GB";
        }

        public Spec keys(KeyPair k) { this.keys = k; return this; }
        public Spec ca() { this.ca = true; return this; }
        public Spec issuedBy(X509Certificate issuerCert, KeyPair issuerKeys) {
            this.issuer = issuerCert.getSubjectX500Principal().getName();
            this.signer = issuerKeys.getPrivate();
            return this;
        }
        public Spec selfSigned() { this.issuer = subject; this.signer = keys.getPrivate(); return this; }
        public Spec validity(Instant nb, Instant na) { this.notBefore = nb; this.notAfter = na; return this; }
        public Spec expired() { return validity(NOW.minus(Duration.ofDays(400)), NOW.minus(Duration.ofDays(5))); }
        public Spec sigAlg(String alg) { this.sigAlg = alg; return this; }
        public Spec aia(String url) { this.aia = url; return this; }
        public Spec serial(BigInteger s) { this.serial = s; return this; }

        public X509Certificate build() {
            try {
                if (issuer == null) selfSigned();
                X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Principal(issuer), serial,
                        Date.from(notBefore), Date.from(notAfter), new X500Principal(subject), keys.getPublic());
                b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
                if (aia != null) {
                    b.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                            AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, aia)));
                }
                return new JcaX509CertificateConverter().getCertificate(
                        b.build(new JcaContentSignerBuilder(sigAlg).build(signer)));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /** root (a trust anchor) → intermediate → leaf, the shape of a normal public chain. */
    public record Chain(X509Certificate root, X509Certificate inter, X509Certificate leaf) {}

    public static Chain chain() {
        X509Certificate root = cert("Test Root").keys(ROOT_KEY).ca().selfSigned().build();
        X509Certificate inter = cert("Test Intermediate").keys(INTER_KEY).ca().issuedBy(root, ROOT_KEY).build();
        X509Certificate leaf = cert("www.example.com").keys(LEAF_KEY).issuedBy(inter, INTER_KEY).build();
        return new Chain(root, inter, leaf);
    }
}
