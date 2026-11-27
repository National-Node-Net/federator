/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.util.Objects;
import lombok.Getter;

/**
 * A gRPC call was ended because the peer's certificate failed a revocation check after the handshake: at the start
 * of the call or at a re-check. On the consumer it is the cause of the call cancellation, so the stream loops can tell
 * it from a normal end of stream.
 */
@Getter
public class PeerCertificateRejectedException extends RuntimeException {

    private final RevocationVerdict verdict;

    public PeerCertificateRejectedException(String serial, RevocationVerdict verdict) {
        super("Peer certificate " + serial + " rejected: revocation status " + verdict.status());
        this.verdict = Objects.requireNonNull(verdict, "verdict");
    }

    /**
     * @return true for {@code revoked} or {@code unknown}, false when the status was unavailable
     */
    public boolean isCertificateRejected() {
        return !verdict.unavailable();
    }
}
