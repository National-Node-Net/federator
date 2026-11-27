/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.math.BigInteger;
import java.util.Locale;
import java.util.Objects;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.util.encoders.Hex;

/**
 * Cache key of a certificate status: the SHA-1 hash of the issuer's public key and the serial number,
 * both lowercase hex without separators ({@code issuerKeyHash:serial}). The Management Node uses the same format.
 *
 * @param issuerKeyHash lowercase hex SHA-1 hash of the issuer's public key
 * @param serial        lowercase hex serial number without separators or leading zeros
 */
public record CertificateKey(String issuerKeyHash, String serial) {

    public CertificateKey {
        Objects.requireNonNull(issuerKeyHash, "issuerKeyHash");
        Objects.requireNonNull(serial, "serial");
    }

    /**
     * Builds the key of an OCSP certificate ID.
     *
     * @param certificateId a certificate ID built with SHA-1
     * @return the cache key
     */
    public static CertificateKey of(CertificateID certificateId) {
        String keyHash = Hex.toHexString(
                certificateId.toASN1Primitive().getIssuerKeyHash().getOctets());
        return new CertificateKey(keyHash, serialHex(certificateId.getSerialNumber()));
    }

    /**
     * Canonical serial format used in keys and logs: lowercase hex, no separators, no leading zeros.
     */
    public static String serialHex(BigInteger serial) {
        return serial.toString(16).toLowerCase(Locale.ROOT);
    }

    @Override
    public String toString() {
        return issuerKeyHash + ":" + serial;
    }
}
