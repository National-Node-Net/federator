/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.client.jobs.handlers;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import uk.gov.dbt.ndtp.federator.client.connection.ConnectionProperties;
import uk.gov.dbt.ndtp.federator.common.metrics.MetricsServer;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationFailures;
import uk.gov.dbt.ndtp.federator.exceptions.RevocationJobException;
import uk.gov.dbt.ndtp.federator.exceptions.RevocationJobException.Reason;

/**
 * Turns a consumer job failure caused by a revocation check into a {@link RevocationJobException}, which JobRunr does
 * not retry, and logs it. Other failures, including an unavailable certificate status, keep the normal retry policy.
 */
@Slf4j
final class RevocationJobFailures {

    static final String JOBS_FAILED = "federator.revocation.jobs.failed";

    private RevocationJobFailures() {}

    /**
     * @return the non-retryable exception to throw instead of {@code failure}, if the failure is a revocation
     *     rejection
     */
    static Optional<RevocationJobException> translate(
            Exception failure, ConnectionProperties producer, String topic, String jobId, MeterRegistry meters) {
        Optional<RevocationFailures.Kind> kind = RevocationFailures.classify(failure);
        if (kind.isEmpty() || kind.get() == RevocationFailures.Kind.PEER_STATUS_UNAVAILABLE) {
            return Optional.empty();
        }
        Reason reason = kind.get() == RevocationFailures.Kind.OWN_CERTIFICATE_REJECTED
                ? Reason.CONSUMER_CERTIFICATE_REJECTED
                : Reason.PRODUCER_CERTIFICATE_REVOKED;
        String producerId = producer == null ? "-" : producer.serverName();
        String address = producer == null ? "-" : producer.serverHost() + ":" + producer.serverPort();
        log.error(
                "event=revocation.job reason={} producer_id={} producer_address={} topic={} job_id={} retry=false"
                        + " detail=\"{}\"",
                reason,
                producerId,
                address,
                topic,
                jobId == null ? "-" : jobId,
                rootMessage(failure));
        Counter.builder(JOBS_FAILED)
                .description("Consumer jobs failed by a revocation rejection (not retried)")
                .tag("reason", reason.name())
                .register(meters)
                .increment();
        return Optional.of(new RevocationJobException(
                reason, "job for producer " + producerId + ", topic " + topic + " is not retried", failure));
    }

    /**
     * Same as {@link #translate(Exception, ConnectionProperties, String, String, MeterRegistry)} with the process-wide
     * registry. The job id is passed explicitly: the job's MDC entry is already closed when its catch block runs.
     */
    static Optional<RevocationJobException> translate(
            Exception failure, ConnectionProperties producer, String topic, String jobId) {
        return translate(failure, producer, topic, jobId, MetricsServer.registry());
    }

    private static String rootMessage(Throwable failure) {
        Throwable root = failure;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        return String.valueOf(root.getMessage()).replace('"', '\'');
    }
}
