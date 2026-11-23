/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.security.cert.X509Certificate;
import java.util.Objects;
import org.bouncycastle.cert.ocsp.CertificateID;

/**
 * A certificate to check together with its issuer, its OCSP certificate ID and its cache key, computed once.
 *
 * @param key           cache key ({@code issuerKeyHash:serial})
 * @param certificateId SHA-1 OCSP certificate ID
 * @param certificate   the peer certificate
 * @param issuer        its issuing CA certificate
 */
public record RevocationTarget(
        CertificateKey key, CertificateID certificateId, X509Certificate certificate, X509Certificate issuer) {

    public RevocationTarget {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(certificateId, "certificateId");
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(issuer, "issuer");
    }

    /**
     * Builds the target of a certificate issued by {@code issuer}.
     */
    public static RevocationTarget of(X509Certificate certificate, X509Certificate issuer) {
        CertificateID certificateId = OcspClient.certificateId(certificate, issuer);
        return new RevocationTarget(CertificateKey.of(certificateId), certificateId, certificate, issuer);
    }

    /** Lowercase hex serial, for logs. */
    public String serial() {
        return key.serial();
    }

    /** Issuer DN of the certificate, for logs. */
    public String issuerName() {
        return certificate.getIssuerX500Principal().getName();
    }
}
