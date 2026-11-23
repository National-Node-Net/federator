/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.server.grpc.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
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

class ActiveCallRegistryTest {

    private static final Instant NOW = Instant.parse("2026-11-18T10:00:00Z");

    private TestPki pki;
    private RevocationChecker checker;
    private SimpleMeterRegistry meters;
    private ScheduledExecutorService scheduler;

    @BeforeEach
    void setUp() {
        pki = new TestPki("Federation CA");
        checker = mock(RevocationChecker.class);
        when(checker.clock()).thenReturn(Clock.fixed(NOW, ZoneOffset.UTC));
        when(checker.expiresAt(any())).thenReturn(NOW.plus(Duration.ofHours(1)));
        meters = new SimpleMeterRegistry();
        scheduler = new ScheduledThreadPoolExecutor(1);
    }

    @AfterEach
    void tearDown() {
        scheduler.shutdownNow();
    }

    private ActiveCallRegistry registry(boolean failClosed) {
        return new ActiveCallRegistry(checker, new RevocationAudit("producer", meters), failClosed, scheduler);
    }

    private RevocationTarget peer(String name) {
        TestPki.Issued issued = pki.node(name);
        return RevocationTarget.of(issued.certificate(), pki.caCertificate());
    }

    @SuppressWarnings("unchecked")
    private static ServerCall<Object, Object> serverCall() {
        return mock(ServerCall.class);
    }

    private static RevocationDecision status(CertificateStatus status) {
        long now = NOW.toEpochMilli();
        return new RevocationDecision.Status(new CertificateStatusEntry(status, now, null, now), false);
    }

    private static Instant later() {
        return NOW.plus(Duration.ofHours(1));
    }

    @Test
    void revokedPeerHasAllItsCallsClosedAndOthersAreUnaffected() {
        ActiveCallRegistry registry = registry(true);
        RevocationTarget revoked = peer("consumer-r");
        RevocationTarget other = peer("consumer-b");
        ServerCall<Object, Object> first = serverCall();
        ServerCall<Object, Object> second = serverCall();
        ServerCall<Object, Object> unrelated = serverCall();
        SSLSession session = mock(SSLSession.class);
        RevocableServerCall<Object, Object> call1 = new RevocableServerCall<>(first, "conn-1", session);
        RevocableServerCall<Object, Object> call2 = new RevocableServerCall<>(second, "conn-2", session);
        RevocableServerCall<Object, Object> call3 = new RevocableServerCall<>(unrelated, "conn-3", null);
        registry.register(revoked, call1, later());
        registry.register(revoked, call2, later());
        registry.register(other, call3, later());
        when(checker.refresh(revoked)).thenReturn(status(CertificateStatus.REVOKED));

        registry.recheck(revoked.key());

        ArgumentCaptor<Status> closed = ArgumentCaptor.forClass(Status.class);
        verify(first).close(closed.capture(), any(Metadata.class));
        verify(second).close(any(Status.class), any(Metadata.class));
        verify(unrelated, never()).close(any(Status.class), any(Metadata.class));
        assertEquals(Status.Code.UNAUTHENTICATED, closed.getValue().getCode());
        assertTrue(call1.isCancelled());
        assertThrows(StatusRuntimeException.class, () -> call1.sendMessage("late data"));
        verify(first, never()).sendMessage(any());
        verify(session, org.mockito.Mockito.atLeastOnce()).invalidate();
        assertEquals(0, registry.openCalls(revoked.key()));
        assertEquals(1, registry.openCalls(other.key()));
        assertEquals(
                2.0,
                meters.get("federator.revocation.connections.terminated")
                        .tag("cause", "revoked")
                        .counter()
                        .count());
    }

    @Test
    void unknownStatusAlsoClosesWithUnauthenticated() {
        ActiveCallRegistry registry = registry(true);
        RevocationTarget peer = peer("consumer-u");
        ServerCall<Object, Object> call = serverCall();
        registry.register(peer, new RevocableServerCall<>(call, "c", null), later());
        when(checker.refresh(any())).thenReturn(status(CertificateStatus.UNKNOWN));

        registry.recheck(peer.key());

        ArgumentCaptor<Status> closed = ArgumentCaptor.forClass(Status.class);
        verify(call).close(closed.capture(), any(Metadata.class));
        assertEquals(Status.Code.UNAUTHENTICATED, closed.getValue().getCode());
    }

    @Test
    void goodStatusKeepsTheCallsOpen() {
        ActiveCallRegistry registry = registry(true);
        RevocationTarget peer = peer("consumer-a");
        ServerCall<Object, Object> call = serverCall();
        registry.register(peer, new RevocableServerCall<>(call, "c", null), later());
        when(checker.refresh(any())).thenReturn(status(CertificateStatus.GOOD));

        registry.recheck(peer.key());

        verify(call, never()).close(any(Status.class), any(Metadata.class));
        assertEquals(1, registry.openCalls(peer.key()));
    }

    @Test
    void responderFailureClosesWithUnavailableWhenFailingClosed() {
        ActiveCallRegistry registry = registry(true);
        RevocationTarget peer = peer("consumer-a");
        ServerCall<Object, Object> call = serverCall();
        registry.register(peer, new RevocableServerCall<>(call, "c", null), later());
        when(checker.refresh(any()))
                .thenReturn(new RevocationDecision.ResponderFailure(
                        new OcspResponderException(OcspResponderException.Type.CIRCUIT_OPEN, "open")));

        registry.recheck(peer.key());

        ArgumentCaptor<Status> closed = ArgumentCaptor.forClass(Status.class);
        verify(call).close(closed.capture(), any(Metadata.class));
        assertEquals(Status.Code.UNAVAILABLE, closed.getValue().getCode());
    }

    @Test
    void responderFailureKeepsCallsWhenFailingOpen() {
        ActiveCallRegistry registry = registry(false);
        RevocationTarget peer = peer("consumer-a");
        ServerCall<Object, Object> call = serverCall();
        registry.register(peer, new RevocableServerCall<>(call, "c", null), later());
        when(checker.refresh(any()))
                .thenReturn(new RevocationDecision.ResponderFailure(
                        new OcspResponderException(OcspResponderException.Type.TIMEOUT, "slow")));

        registry.recheck(peer.key());

        verify(call, never()).close(any(Status.class), any(Metadata.class));
        assertEquals(1, registry.openCalls(peer.key()));
    }

    @Test
    void closedCallsAreUnregisteredAndNotRechecked() {
        ActiveCallRegistry registry = registry(true);
        RevocationTarget peer = peer("consumer-a");
        RevocableServerCall<Object, Object> call = new RevocableServerCall<>(serverCall(), "c", null);
        registry.register(peer, call, later());

        call.close(Status.OK, new Metadata());
        registry.recheck(peer.key());

        assertEquals(0, registry.openCalls(peer.key()));
        verify(checker, never()).refresh(any());
    }

    @Test
    void recheckRunsWhenTheCacheEntryExpires() {
        ActiveCallRegistry registry = registry(true);
        RevocationTarget peer = peer("consumer-a");
        ServerCall<Object, Object> call = serverCall();
        when(checker.refresh(any())).thenReturn(status(CertificateStatus.REVOKED));

        // the clock is fixed, so a recheck time at "now" is due immediately
        registry.register(peer, new RevocableServerCall<>(call, "c", null), NOW);

        org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> verify(call)
                .close(any(Status.class), any(Metadata.class)));
        assertFalse(registry.openCalls(peer.key()) > 0);
    }
}
