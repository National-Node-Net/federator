/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Optional;
import java.util.Set;

/**
 * Classifies failures of a consumer job by walking the cause chain.
 */
public final class RevocationFailures {

    /** What a failure says about certificates. */
    public enum Kind {
        /** The producer's certificate is revoked or unknown (handshake, call start or re-check). */
        PEER_CERTIFICATE_REJECTED,
        /** The producer's certificate status could not be obtained and checks fail closed. */
        PEER_STATUS_UNAVAILABLE,
        /** The producer rejected this federator's own certificate as revoked or unknown. */
        OWN_CERTIFICATE_REJECTED
    }

    private RevocationFailures() {}

    /**
     * @return the kind of revocation failure in the cause chain, if any
     */
    public static Optional<Kind> classify(Throwable failure) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable t = failure; t != null && seen.add(t); t = t.getCause()) {
            if (t instanceof RevokedPeerCertificateException revoked) {
                return Optional.of(
                        revoked.isCertificateRejected()
                                ? Kind.PEER_CERTIFICATE_REJECTED
                                : Kind.PEER_STATUS_UNAVAILABLE);
            }
            if (t instanceof PeerCertificateRejectedException rejected) {
                return Optional.of(
                        rejected.isCertificateRejected()
                                ? Kind.PEER_CERTIFICATE_REJECTED
                                : Kind.PEER_STATUS_UNAVAILABLE);
            }
            if (t instanceof StatusRuntimeException sre && isOwnCertificateRejection(sre.getStatus())) {
                return Optional.of(Kind.OWN_CERTIFICATE_REJECTED);
            }
        }
        return Optional.empty();
    }

    /** The producer closes a call of a revoked or unknown consumer with UNAUTHENTICATED "Peer certificate ...". */
    private static boolean isOwnCertificateRejection(Status status) {
        String description = status.getDescription();
        return status.getCode() == Status.Code.UNAUTHENTICATED
                && description != null
                && (description.equals("Peer certificate revoked") || description.equals("Peer certificate unknown"));
    }
}
