/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import io.grpc.Status;
import java.io.Serializable;

/**
 * What to do with a peer, given a revocation decision: the single place where the enforcement policy is applied.
 * <ul>
 *     <li>{@code good}: allowed.</li>
 *     <li>{@code revoked} / {@code unknown}: rejected with {@code UNAUTHENTICATED}.</li>
 *     <li>No status available: rejected with {@code UNAVAILABLE} when failing closed, otherwise allowed.</li>
 * </ul>
 *
 * @param allowed whether the peer may proceed
 * @param status  {@code good}, {@code revoked}, {@code unknown} or {@code unavailable}
 * @param cause   {@code none} for an allowed good certificate, otherwise the status
 */
public record RevocationVerdict(boolean allowed, String status, String cause) implements Serializable {

    public static RevocationVerdict of(RevocationDecision decision, boolean failClosed) {
        String status = decision.statusTag();
        if (decision.isGood()) {
            return new RevocationVerdict(true, status, "none");
        }
        boolean unavailable = decision instanceof RevocationDecision.ResponderFailure;
        return new RevocationVerdict(unavailable && !failClosed, status, status);
    }

    /**
     * @return true when the verdict was taken without a valid status
     */
    public boolean unavailable() {
        return RevocationDecision.UNAVAILABLE.equals(status);
    }

    /**
     * @return the gRPC status a rejected call is closed with
     */
    public Status rejection() {
        return unavailable()
                ? Status.UNAVAILABLE.withDescription("Peer certificate status unavailable")
                : Status.UNAUTHENTICATED.withDescription("Peer certificate " + status);
    }
}
