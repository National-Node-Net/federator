/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.client.grpc.revocation;

import io.grpc.Context;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.MDC;
import uk.gov.dbt.ndtp.federator.common.revocation.PeerCertificateRejectedException;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationVerdict;

/**
 * Per-call flag shared between the consumer's stream loop and the revocation checks of that call.
 * <p>
 * The loop creates it, starts the call in a gRPC {@link Context} carrying it ({@link #CONTEXT_KEY}, read by the
 * revocation interceptor when the call is created) and calls {@link #ensureAccepted()} before it writes a message to
 * Kafka or file storage or saves an offset. The revocation interceptor or the re-check marks it rejected before
 * cancelling the call, so a message that was already received is discarded instead of written.
 */
public final class RevocationGuard {

    /** Context key carrying the guard from the stream loop to the revocation interceptor. */
    public static final Context.Key<RevocationGuard> CONTEXT_KEY = Context.key("federator-revocation-guard");

    /** MDC key the consumer jobs set to their job id; it is copied into the guard for the logs. */
    public static final String MDC_JOB_ID = "job_id";

    private final String producerId;
    private final String topic;
    private final String jobId;
    private final AtomicReference<PeerCertificateRejectedException> rejection = new AtomicReference<>();

    public RevocationGuard(String producerId, String topic) {
        this.producerId = producerId;
        this.topic = topic;
        this.jobId = MDC.get(MDC_JOB_ID);
    }

    /**
     * Creates a call with the guard in the current gRPC context, so the revocation interceptor finds it.
     */
    public static <T> T withGuard(RevocationGuard guard, Callable<T> createCall) {
        try {
            return Context.current().withValue(CONTEXT_KEY, guard).call(createCall);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Could not start the gRPC call", e);
        }
    }

    /** Marks the call rejected; the first rejection wins. */
    public void reject(String serial, RevocationVerdict verdict) {
        rejection.compareAndSet(null, new PeerCertificateRejectedException(serial, verdict));
    }

    /**
     * @return true once the producer's certificate has been rejected for this call
     */
    public boolean isRejected() {
        return rejection.get() != null;
    }

    /**
     * @throws PeerCertificateRejectedException when the producer's certificate was rejected; nothing received after
     *     that point may be written
     */
    public void ensureAccepted() {
        PeerCertificateRejectedException rejected = rejection.get();
        if (rejected != null) {
            throw rejected;
        }
    }

    /**
     * @return key=value context for the revocation logs
     */
    public String context() {
        return "producer_id=" + value(producerId) + " topic=" + value(topic) + " job_id=" + value(jobId);
    }

    private static String value(String v) {
        return v == null || v.isBlank() ? "-" : v;
    }
}
