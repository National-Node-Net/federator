/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation.support;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Test PKI built with Bouncy Castle: a federation CA, node certificates and OCSP signer certificates, all EC P-256
 * like the Management Node's signer.
 */
public final class TestPki {

    private static final AtomicLong SERIALS = new AtomicLong(0x1000);

    /** A certificate and its key pair. */
    public record Issued(X509Certificate certificate, KeyPair keyPair) {}

    private final Issued ca;

    public TestPki(String caName) {
        KeyPair caKeys = newKeyPair();
        this.ca = new Issued(selfSignedCa(caName, caKeys), caKeys);
    }

    public Issued ca() {
        return ca;
    }

    public X509Certificate caCertificate() {
        return ca.certificate();
    }

    /** A node certificate (serverAuth + clientAuth, SAN localhost), like the ones issued through default-role. */
    public Issued node(String commonName) {
        return issue(
                commonName,
                nextSerial(),
                new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth},
                Duration.ofDays(30),
                true);
    }

    /** A node certificate with a given serial (e.g. with a leading zero byte). */
    public Issued node(String commonName, BigInteger serial) {
        return issue(
                commonName,
                serial,
                new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth},
                Duration.ofDays(30),
                true);
    }

    /** A delegated OCSP signer with {@code id-kp-OCSPSigning}. */
    public Issued ocspSigner(String commonName) {
        return issue(
                commonName,
                nextSerial(),
                new KeyPurposeId[] {KeyPurposeId.id_kp_OCSPSigning},
                Duration.ofDays(1),
                false);
    }

    /** A signer issued like today's Management Node signer: default-role usages, no {@code id-kp-OCSPSigning}. */
    public Issued signerWithoutOcspEku(String commonName) {
        return node(commonName);
    }

    /** An expired delegated OCSP signer. */
    public Issued expiredOcspSigner(String commonName) {
        return issue(
                commonName,
                nextSerial(),
                new KeyPurposeId[] {KeyPurposeId.id_kp_OCSPSigning},
                Duration.ofDays(-1),
                false);
    }

    private Issued issue(String commonName, BigInteger serial, KeyPurposeId[] eku, Duration validity, boolean san) {
        try {
            KeyPair keys = newKeyPair();
            Instant now = Instant.now();
            Instant notBefore =
                    validity.isNegative() ? now.minus(Duration.ofDays(2)) : now.minus(Duration.ofMinutes(5));
            Instant notAfter = validity.isNegative() ? now.minus(Duration.ofDays(1)) : now.plus(validity);
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    ca.certificate(),
                    serial,
                    Date.from(notBefore),
                    Date.from(notAfter),
                    new X500Name("CN=" + commonName + ",O=Test"),
                    keys.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(
                    Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement));
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
            if (san) {
                builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[] {
                    new GeneralName(GeneralName.dNSName, "localhost"),
                    new GeneralName(GeneralName.iPAddress, "127.0.0.1")
                }));
            }
            X509Certificate certificate = new JcaX509CertificateConverter()
                    .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                            .build(ca.keyPair().getPrivate())));
            return new Issued(certificate, keys);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot issue test certificate", e);
        }
    }

    private static X509Certificate selfSignedCa(String name, KeyPair keys) {
        try {
            X500Name subject = new X500Name("CN=" + name + ",O=Test");
            Instant now = Instant.now();
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subject,
                    nextSerial(),
                    Date.from(now.minus(Duration.ofDays(1))),
                    Date.from(now.plus(Duration.ofDays(365))),
                    subject,
                    keys.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
            return new JcaX509CertificateConverter()
                    .getCertificate(
                            builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot create test CA", e);
        }
    }

    public static KeyPair newKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static BigInteger nextSerial() {
        return BigInteger.valueOf(SERIALS.incrementAndGet())
                .shiftLeft(40)
                .add(BigInteger.valueOf(System.nanoTime() & 0xFFFFFF));
    }

    /** PKIX trust manager trusting only the given CA certificates. */
    public static X509ExtendedTrustManager trustManager(X509Certificate... cas) {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            for (int i = 0; i < cas.length; i++) {
                store.setCertificateEntry("ca" + i, cas[i]);
            }
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(store);
            return (X509ExtendedTrustManager) factory.getTrustManagers()[0];
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Key manager factory holding one certificate (with the CA in the chain). */
    public KeyManagerFactory keyManagerFactory(Issued issued) {
        try {
            char[] password = "changeit".toCharArray();
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            store.setKeyEntry("key", issued.keyPair().getPrivate(), password, new X509Certificate[] {
                issued.certificate(), ca.certificate()
            });
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(store, password);
            return factory;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
