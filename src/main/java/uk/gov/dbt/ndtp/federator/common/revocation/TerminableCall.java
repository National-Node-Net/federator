/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

/**
 * An open gRPC call that the {@link ActiveCallRegistry} can end when the peer's certificate fails a re-check:
 * a server call (producer side) is closed, a client call (consumer side) is cancelled and its channel shut down.
 */
public interface TerminableCall {

    /**
     * @return identifier of the TLS connection of the call, for logs (see {@link ConnectionIds})
     */
    String connectionId();

    /**
     * @return extra key=value context for logs, e.g. {@code producer_id=... job_id=...}, or null
     */
    default String context() {
        return null;
    }

    /**
     * Ends the call because of a failed revocation check, unless it is already closed.
     *
     * @param verdict the rejecting verdict
     * @return true when this method ended the call
     */
    boolean terminate(RevocationVerdict verdict);

    /**
     * Registers a callback that runs once when the call ends, for whatever reason.
     */
    void onClosed(Runnable callback);
}
