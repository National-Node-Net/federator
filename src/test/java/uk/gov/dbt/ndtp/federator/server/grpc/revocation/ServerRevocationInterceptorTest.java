/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.server.grpc.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.grpc.Attributes;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.Status;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.dbt.ndtp.federator.common.revocation.CertificateStatus;
import uk.gov.dbt.ndtp.federator.common.revocation.CertificateStatusEntry;
import uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationChecker;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationDecision;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationTarget;
import uk.gov.dbt.ndtp.federator.common.revocation.support.TestPki;

class ServerRevocationInterceptorTest {

    private static final Instant NOW = Instant.parse("2026-11-18T10:00:00Z");

    private TestPki pki;
    private TestPki.Issued consumer;
    private RevocationChecker checker;
    private ActiveCallRegistry registry;
    private ScheduledThreadPoolExecutor scheduler;
    private ServerCall<Object, Object> call;
    private ServerCallHandler<Object, Object> next;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() throws Exception {
        pki = new TestPki("Federation CA");
        consumer = pki.node("consumer-a");
        checker = mock(RevocationChecker.class);
        when(checker.clock()).thenReturn(Clock.fixed(NOW, ZoneOffset.UTC));
        when(checker.expiresAt(any())).thenReturn(NOW.plus(Duration.ofMinutes(5)));
        scheduler = new ScheduledThreadPoolExecutor(1);
        registry = new ActiveCallRegistry(
                checker, new RevocationAudit("producer", new SimpleMeterRegistry()), true, scheduler);

        SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(new Certificate[] {consumer.certificate(), pki.caCertificate()});
        when(session.getId()).thenReturn(new byte[] {1, 2, 3});
        call = mock(ServerCall.class);
        when(call.getAttributes())
                .thenReturn(Attributes.newBuilder()
                        .set(Grpc.TRANSPORT_ATTR_SSL_SESSION, session)
                        .set(Grpc.TRANSPORT_ATTR_REMOTE_ADDR, new InetSocketAddress("127.0.0.1", 50000))
                        .build());
        next = mock(ServerCallHandler.class);
        when(next.startCall(any(), any())).thenReturn(new ServerCall.Listener<>() {});
    }

    @AfterEach
    void tearDown() {
        scheduler.shutdownNow();
    }

    private ServerRevocationInterceptor interceptor(boolean failClosed) {
        return new ServerRevocationInterceptor(
                checker,
                registry,
                new RevocationAudit("producer", new SimpleMeterRegistry()),
                List.of(pki.caCertificate()),
                failClosed);
    }

    private static RevocationDecision status(CertificateStatus status) {
        long now = NOW.toEpochMilli();
        return new RevocationDecision.Status(new CertificateStatusEntry(status, now, null, now), true);
    }

    private Status closedWith() {
        ArgumentCaptor<Status> status = ArgumentCaptor.forClass(Status.class);
        verify(call).close(status.capture(), any(Metadata.class));
        return status.getValue();
    }

    @Test
    void goodCertificateProceedsAndTheCallIsRegistered() {
        when(checker.check(any())).thenReturn(status(CertificateStatus.GOOD));

        interceptor(true).interceptCall(call, new Metadata(), next);

        ArgumentCaptor<ServerCall<Object, Object>> started = ArgumentCaptor.forClass(ServerCall.class);
        verify(next).startCall(started.capture(), any());
        assertInstanceOf(RevocableServerCall.class, started.getValue());
        assertEquals(
                1,
                registry.openCalls(RevocationTarget.of(consumer.certificate(), pki.caCertificate())
                        .key()));
    }

    @Test
    void issuerAndCertificateIdAreResolvedOncePerTlsSession() throws Exception {
        SSLSession session = call.getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION);
        when(checker.check(any())).thenReturn(status(CertificateStatus.GOOD));

        interceptor(true).interceptCall(call, new Metadata(), next);
        ArgumentCaptor<Object> stored = ArgumentCaptor.forClass(Object.class);
        verify(session)
                .putValue(
                        org.mockito.ArgumentMatchers.eq(ServerRevocationInterceptor.SESSION_TARGET), stored.capture());
        assertInstanceOf(RevocationTarget.class, stored.getValue());

        when(session.getValue(ServerRevocationInterceptor.SESSION_TARGET)).thenReturn(stored.getValue());
        interceptor(true).interceptCall(call, new Metadata(), next);

        verify(session, times(1)).getPeerCertificates();
        verify(checker, times(2)).check(any());
    }

    @Test
    void cachedRevokedStatusClosesTheCallBeforeTheNextInterceptor() {
        when(checker.check(any())).thenReturn(status(CertificateStatus.REVOKED));

        interceptor(true).interceptCall(call, new Metadata(), next);

        assertEquals(Status.Code.UNAUTHENTICATED, closedWith().getCode());
        verify(next, never()).startCall(any(), any());
    }

    @Test
    void unknownStatusClosesWithUnauthenticated() {
        when(checker.check(any())).thenReturn(status(CertificateStatus.UNKNOWN));
        interceptor(true).interceptCall(call, new Metadata(), next);
        assertEquals(Status.Code.UNAUTHENTICATED, closedWith().getCode());
    }

    @Test
    void unavailableStatusClosesWithUnavailableWhenFailingClosed() {
        when(checker.check(any()))
                .thenReturn(new RevocationDecision.ResponderFailure(
                        new OcspResponderException(OcspResponderException.Type.CIRCUIT_OPEN, "open")));

        interceptor(true).interceptCall(call, new Metadata(), next);

        assertEquals(Status.Code.UNAVAILABLE, closedWith().getCode());
        verify(next, never()).startCall(any(), any());
    }

    @Test
    void unavailableStatusProceedsWhenFailingOpen() {
        when(checker.check(any()))
                .thenReturn(new RevocationDecision.ResponderFailure(
                        new OcspResponderException(OcspResponderException.Type.TIMEOUT, "slow")));

        interceptor(false).interceptCall(call, new Metadata(), next);

        verify(next).startCall(any(), any());
    }

    @Test
    void callWithoutClientCertificateIsRejected() throws Exception {
        SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenThrow(new SSLPeerUnverifiedException("none"));
        when(call.getAttributes())
                .thenReturn(Attributes.newBuilder()
                        .set(Grpc.TRANSPORT_ATTR_SSL_SESSION, session)
                        .build());

        interceptor(true).interceptCall(call, new Metadata(), next);

        assertEquals(Status.Code.UNAUTHENTICATED, closedWith().getCode());
        verify(checker, never()).check(any());
    }

    @Test
    void callWithEmptyPeerChainIsRejected() throws Exception {
        SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(new Certificate[0]);
        when(call.getAttributes())
                .thenReturn(Attributes.newBuilder()
                        .set(Grpc.TRANSPORT_ATTR_SSL_SESSION, session)
                        .build());

        interceptor(true).interceptCall(call, new Metadata(), next);

        assertEquals(Status.Code.UNAUTHENTICATED, closedWith().getCode());
        verify(checker, never()).check(any());
    }

    @Test
    void callWithoutTlsSessionIsRejected() {
        when(call.getAttributes()).thenReturn(Attributes.EMPTY);
        interceptor(true).interceptCall(call, new Metadata(), next);
        assertEquals(Status.Code.UNAUTHENTICATED, closedWith().getCode());
    }
}
