/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.exceptions;

import lombok.Getter;
import org.jobrunr.JobRunrException;

/**
 * A consumer job failed because a certificate failed a revocation check. JobRunr does not retry it
 * ({@code doNotRetry}), so a revoked producer does not cause a retry storm; the next scheduled run is rejected in the
 * TLS handshake from the cached status, without asking the OCSP responder again.
 */
@Getter
public class RevocationJobException extends JobRunrException {

    /** Failure reason, also logged and used as metric tag. */
    public enum Reason {
        /** The producer's server certificate is revoked or unknown. */
        PRODUCER_CERTIFICATE_REVOKED,
        /** The producer rejected this federator's own client certificate as revoked or unknown. */
        CONSUMER_CERTIFICATE_REJECTED
    }

    private final Reason reason;

    public RevocationJobException(Reason reason, String message, Throwable cause) {
        super(reason + ": " + message, true, cause);
        this.reason = reason;
    }
}
