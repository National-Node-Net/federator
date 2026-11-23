/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.client.jobs.handlers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.Test;
import uk.gov.dbt.ndtp.federator.WrappedGRPCClient;
import uk.gov.dbt.ndtp.federator.client.connection.ConnectionProperties;
import uk.gov.dbt.ndtp.federator.client.jobs.params.ClientGRPCJobParams;
import uk.gov.dbt.ndtp.federator.common.revocation.PeerCertificateRejectedException;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationFailures;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationVerdict;
import uk.gov.dbt.ndtp.federator.common.revocation.RevokedPeerCertificateException;
import uk.gov.dbt.ndtp.federator.common.revocation.support.RevocationTestSupport;
import uk.gov.dbt.ndtp.federator.exceptions.ClientGRPCJobException;
import uk.gov.dbt.ndtp.federator.exceptions.RevocationJobException;

class RevocationJobFailuresTest {

    private static final ConnectionProperties PRODUCER =
            new ConnectionProperties("consumer", "key", "ProducerA", "localhost", 8089, true);

    /** A handshake failure as gRPC reports it: UNAVAILABLE with the trust manager's exception in the chain. */
    private static Exception handshakeFailure(String status) {
        SSLHandshakeException ssl = new SSLHandshakeException("handshake failed");
        ssl.initCause(new RevokedPeerCertificateException("4a1f", status));
        return new ClientGRPCJobException("wrapped", new StatusRuntimeException(Status.UNAVAILABLE.withCause(ssl)));
    }

    @Test
    void revokedProducerAtTheHandshakeIsNotRetried() {
        SimpleMeterRegistry meters = new SimpleMeterRegistry();
        RevocationJobException translated = RevocationJobFailures.translate(
                        handshakeFailure("revoked"), PRODUCER, "topic", "job-1", meters)
                .orElseThrow();
        assertEquals(RevocationJobException.Reason.PRODUCER_CERTIFICATE_REVOKED, translated.getReason());
        assertTrue(translated.isProblematicAndDoNotRetry(), "JobRunr must not retry");
        assertEquals(
                1.0,
                meters.get(RevocationJobFailures.JOBS_FAILED)
                        .tag("reason", "PRODUCER_CERTIFICATE_REVOKED")
                        .counter()
                        .count());
    }

    @Test
    void producerRevokedDuringTheCallIsNotRetried() {
        Exception failure = new ClientGRPCJobException(
                "wrapped",
                new StatusRuntimeException(Status.CANCELLED.withCause(new PeerCertificateRejectedException(
                        "4a1f", new RevocationVerdict(false, "unknown", "unknown")))));
        assertEquals(
                RevocationJobException.Reason.PRODUCER_CERTIFICATE_REVOKED,
                RevocationJobFailures.translate(failure, PRODUCER, "topic", "job-1", new SimpleMeterRegistry())
                        .orElseThrow()
                        .getReason());
    }

    @Test
    void ownCertificateRejectedByTheProducerIsNotRetried() {
        Exception failure =
                new StatusRuntimeException(Status.UNAUTHENTICATED.withDescription("Peer certificate revoked"));
        assertEquals(
                RevocationJobException.Reason.CONSUMER_CERTIFICATE_REJECTED,
                RevocationJobFailures.translate(failure, PRODUCER, "topic", "job-1", new SimpleMeterRegistry())
                        .orElseThrow()
                        .getReason());
        assertEquals(
                RevocationFailures.Kind.OWN_CERTIFICATE_REJECTED,
                RevocationFailures.classify(failure).orElseThrow());
    }

    @Test
    void unavailableStatusAndOtherFailuresKeepTheNormalRetry() {
        SimpleMeterRegistry meters = new SimpleMeterRegistry();
        assertTrue(RevocationJobFailures.translate(handshakeFailure("unavailable"), PRODUCER, "t", "job-1", meters)
                .isEmpty());
        assertTrue(RevocationJobFailures.translate(new RuntimeException("kafka down"), PRODUCER, "t", "job-1", meters)
                .isEmpty());
        assertTrue(RevocationJobFailures.translate(
                        new StatusRuntimeException(Status.UNAUTHENTICATED.withDescription("Invalid token")),
                        PRODUCER,
                        "t",
                        "job-1",
                        meters)
                .isEmpty());
    }

    @Test
    void clientGrpcJobThrowsTheNonRetryableException() throws Exception {
        WrappedGRPCClient client = mock(WrappedGRPCClient.class);
        when(client.getRedisPrefix()).thenReturn("prefix");
        doThrow(new ClientGRPCJobException("stream failed", handshakeFailure("revoked")))
                .when(client)
                .processTopic(anyString(), anyLong());
        ClientGRPCJobParams params = new ClientGRPCJobParams();
        params.setTopic("topic");
        params.setJobName("ProducerA");
        params.setConnectionProperties(PRODUCER);
        ClientGRPCJob job = new ClientGRPCJob(params);
        job.setPrefixSupplier(() -> "federated");
        job.setOffsetProvider((prefix, topic) -> 0L);
        job.setClientFactory((config, prefix) -> client);

        String logger = RevocationJobFailures.class.getName();
        ListAppender<ILoggingEvent> logs = RevocationTestSupport.captureLogs(logger);
        try {
            RevocationJobException thrown = assertThrows(RevocationJobException.class, () -> job.run(params));
            assertTrue(thrown.isProblematicAndDoNotRetry());
            assertTrue(
                    logs.list.stream().anyMatch(e -> e.getFormattedMessage().contains("job_id=ProducerA-topic ")),
                    "the job id is logged although the job's MDC entry is closed by then");
        } finally {
            RevocationTestSupport.detach(logger, logs);
        }

        doThrow(new ClientGRPCJobException("kafka", new RuntimeException("down")))
                .when(client)
                .processTopic(any(), anyLong());
        assertInstanceOf(ClientGRPCJobException.class, assertThrows(RuntimeException.class, () -> job.run(params)));
    }
}
