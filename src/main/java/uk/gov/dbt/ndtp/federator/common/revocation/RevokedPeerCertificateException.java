/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.security.cert.CertificateException;
import lombok.Getter;

/**
 * Thrown by {@link OcspTrustManager} when the peer's certificate fails the revocation check in the TLS handshake.
 * It stays in the cause chain of the handshake failure, so callers can tell a revoked peer from other TLS errors.
 */
@Getter
public class RevokedPeerCertificateException extends CertificateException {

    /** {@code revoked}, {@code unknown} or {@code unavailable}. */
    private final String status;

    /** Lowercase hex serial of the peer certificate. */
    private final String serial;

    public RevokedPeerCertificateException(String serial, String status) {
        super("Peer certificate " + serial + " rejected: revocation status " + status);
        this.serial = serial;
        this.status = status;
    }

    /**
     * @return true for {@code revoked} or {@code unknown}: the certificate itself is not acceptable, as opposed to a
     *     status that could not be obtained
     */
    public boolean isCertificateRejected() {
        return !RevocationDecision.UNAVAILABLE.equals(status);
    }
}
