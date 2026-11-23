/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.server.grpc;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.grpc.ConnectivityState;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit;
import uk.gov.dbt.ndtp.federator.common.revocation.support.RevocationTestSupport;
import uk.gov.dbt.ndtp.federator.common.revocation.support.StubOcspResponder;
import uk.gov.dbt.ndtp.federator.common.revocation.support.StubOcspResponder.Answer;
import uk.gov.dbt.ndtp.federator.common.revocation.support.TestPki;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.server.grpc.revocation.ServerRevocationSetup;
import uk.gov.dbt.ndtp.grpc.FederatorServiceGrpc;
import uk.gov.dbt.ndtp.grpc.KafkaByteBatch;
import uk.gov.dbt.ndtp.grpc.TopicRequest;

/**
 * End-to-end revocation checks on a real Netty gRPC server with mutual TLS, the producer's revocation trust manager
 * and interceptor, and a stub OCSP responder following the Management Node contract. Cache TTL is 2 s.
 */
class GRPCServerRevocationTest {

    private static final Duration TTL = Duration.ofSeconds(2);
    /** TTL + OCSP budget (1 s x 2 attempts) + scheduling slack. */
    private static final Duration DETECTION_BOUND = Duration.ofSeconds(6);
    /** server.maxConnectionIdle for these tests (60 s by default with revocation checks active). */
    private static final long MAX_CONNECTION_IDLE_SECONDS = 2;

    @TempDir
    Path tempDir;

    private TestPki pki;
    private StubOcspResponder stub;
    private ServerRevocationSetup.Components components;
    private Server server;
    private StreamingService service;
    private final List<ManagedChannel> channels = new ArrayList<>();
    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void setUp() throws Exception {
        pki = new TestPki("Federation CA");
        stub = new StubOcspResponder(pki);
        RevocationTestSupport.initProperties(
                tempDir,
                Map.of(
                        "management.node.base.url", stub.baseUrl(),
                        "revocation.cache.ttl.seconds", String.valueOf(TTL.toSeconds()),
                        "revocation.ocsp.requestTimeout", "1"));
        logs = RevocationTestSupport.captureLogs("RevocationAudit");

        components = ServerRevocationSetup.create(
                        true,
                        TestPki.trustManager(pki.caCertificate()),
                        HttpClient::newHttpClient,
                        RevocationTestSupport.tokenService(),
                        new SimpleMeterRegistry())
                .orElseThrow();
        TestPki.Issued producer = pki.node("producer");
        service = new StreamingService();
        server = NettyServerBuilder.forPort(0)
                .sslContext(GRPCServer.buildSslContext(
                        pki.keyManagerFactory(producer).getKeyManagers()[0], components.trustManager()))
                .addService(ServerInterceptors.intercept(service, components.interceptor()))
                .maxConnectionIdle(MAX_CONNECTION_IDLE_SECONDS, TimeUnit.SECONDS)
                .build()
                .start();
    }

    @AfterEach
    void tearDown() throws Exception {
        channels.forEach(ManagedChannel::shutdownNow);
        server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        components.close();
        stub.close();
        RevocationTestSupport.detach("RevocationAudit", logs);
        PropertyUtil.clear();
    }

    private ManagedChannel channel(TestPki.Issued consumer) throws Exception {
        ManagedChannel channel = NettyChannelBuilder.forAddress("localhost", server.getPort())
                .sslContext(GrpcSslContexts.forClient()
                        .keyManager(pki.keyManagerFactory(consumer))
                        .trustManager(pki.caCertificate())
                        .build())
                .build();
        channels.add(channel);
        return channel;
    }

    private static KafkaByteBatch firstMessage(ManagedChannel channel) {
        Iterator<KafkaByteBatch> stream = FederatorServiceGrpc.newBlockingStub(channel)
                .withDeadlineAfter(5, TimeUnit.SECONDS)
                .getKafkaConsumer(TopicRequest.getDefaultInstance());
        return stream.next();
    }

    @Test
    void goodConsumerConnectsAndStreams() throws Exception {
        TestPki.Issued consumer = pki.node("consumer-a");
        firstMessage(channel(consumer));
        assertEquals(1, stub.requests(), "one OCSP request at the handshake, the call is served from the cache");
    }

    @Test
    void revokedConsumerIsRejectedAtTheHandshake() throws Exception {
        TestPki.Issued consumer = pki.node("consumer-r");
        stub.answer(consumer.certificate().getSerialNumber(), Answer.REVOKED);

        ManagedChannel rejected = channel(consumer);
        StatusRuntimeException e = assertThrows(StatusRuntimeException.class, () -> firstMessage(rejected));

        assertEquals(Status.Code.UNAVAILABLE, e.getStatus().getCode());
        assertEquals(0, service.calls.get(), "no call reached the service");
    }

    @Test
    void unknownConsumerIsRejectedAtTheHandshake() throws Exception {
        TestPki.Issued consumer = pki.node("consumer-u");
        stub.answer(consumer.certificate().getSerialNumber(), Answer.UNKNOWN);
        ManagedChannel rejected = channel(consumer);
        assertThrows(StatusRuntimeException.class, () -> firstMessage(rejected));
        assertEquals(0, service.calls.get());
    }

    @Test
    void cachedStatusAvoidsNetworkCallsOnNewConnections() throws Exception {
        TestPki.Issued consumer = pki.node("consumer-a");
        firstMessage(channel(consumer));
        firstMessage(channel(consumer));
        assertEquals(1, stub.requests());
    }

    @Test
    void revocationDuringAStreamClosesOnlyThatConsumerAndBlocksReconnection() throws Exception {
        TestPki.Issued revoked = pki.node("consumer-r");
        TestPki.Issued other = pki.node("consumer-b");
        ManagedChannel revokedChannel = channel(revoked);
        RecordingObserver revokedStream = stream(revokedChannel);
        RecordingObserver otherStream = stream(channel(other));
        await().atMost(Duration.ofSeconds(5))
                .until(() -> revokedStream.messages.get() > 0 && otherStream.messages.get() > 0);

        long revokedAt = System.nanoTime();
        stub.answer(revoked.certificate().getSerialNumber(), Answer.REVOKED);

        await().atMost(DETECTION_BOUND).until(() -> revokedStream.error.get() != null);
        Duration detection = Duration.ofNanos(System.nanoTime() - revokedAt);
        assertEquals(
                Status.Code.UNAUTHENTICATED,
                Status.fromThrowable(revokedStream.error.get()).getCode());
        assertTrue(detection.compareTo(DETECTION_BOUND) <= 0, "closed after " + detection);
        await().atMost(Duration.ofSeconds(5)).until(() -> service.terminatedLoops.get() >= 1);

        int otherBefore = otherStream.messages.get();
        await().atMost(Duration.ofSeconds(3)).until(() -> otherStream.messages.get() > otherBefore);
        assertEquals(null, otherStream.error.get(), "other consumer unaffected");

        // the revoked consumer never shuts its channel down: the server closes the now idle connection
        assertEquals(ConnectivityState.READY, revokedChannel.getState(false), "connection still open after the calls");
        await().atMost(Duration.ofSeconds(MAX_CONNECTION_IDLE_SECONDS + 3))
                .until(() -> revokedChannel.getState(false) != ConnectivityState.READY);
        assertEquals(ConnectivityState.READY, channels.get(1).getState(false), "streaming consumer kept");

        ManagedChannel reconnect = channel(revoked);
        assertThrows(StatusRuntimeException.class, () -> firstMessage(reconnect));
        assertTrue(logs.list.stream()
                .anyMatch(e -> e.getFormattedMessage().contains("phase=recheck")
                        && e.getFormattedMessage().contains("result=close")
                        && e.getFormattedMessage()
                                .contains("peer_serial="
                                        + revoked.certificate()
                                                .getSerialNumber()
                                                .toString(16))));
    }

    @Test
    void responderOutageAfterExpiryClosesOpenCallsWithAnAlert() throws Exception {
        RecordingObserver stream = stream(channel(pki.node("consumer-a")));
        await().atMost(Duration.ofSeconds(5)).until(() -> stream.messages.get() > 0);

        stub.httpStatus(503);

        await().atMost(DETECTION_BOUND).until(() -> stream.error.get() != null);
        assertEquals(
                Status.Code.UNAVAILABLE,
                Status.fromThrowable(stream.error.get()).getCode());
        assertTrue(logs.list.stream()
                .anyMatch(e -> e.getLevel() == Level.ERROR
                        && e.getMarkerList() != null
                        && e.getMarkerList().stream().anyMatch(m -> RevocationAudit.SECURITY_ALERT.equals(m.getName()))
                        && e.getFormattedMessage().endsWith("alert=" + RevocationAudit.SECURITY_ALERT)));
    }

    @Test
    void handshakeAndCallLogsShareTheTlsSessionPartOfTheConnectionId() throws Exception {
        ch.qos.logback.classic.Logger audit =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("RevocationAudit");
        Level previous = audit.getLevel();
        audit.setLevel(Level.DEBUG); // allowed decisions are logged at DEBUG
        try {
            firstMessage(channel(pki.node("consumer-a")));

            String handshake = connectionIdOf("phase=handshake");
            String call = connectionIdOf("phase=call");
            String session = handshake.substring(handshake.indexOf('/'));
            assertTrue(session.length() > 1, "handshake log carries the TLS session id: " + handshake);
            assertTrue(call.endsWith(session), "call " + call + " and handshake " + handshake + " match");
            assertTrue(call.startsWith("/127.0.0.1:"), "call log carries the remote address: " + call);
        } finally {
            audit.setLevel(previous);
        }
    }

    private String connectionIdOf(String phase) {
        String line = logs.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .filter(m -> m.contains(phase))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no log line with " + phase));
        java.util.regex.Matcher m =
                java.util.regex.Pattern.compile("connection_id=(\\S+)").matcher(line);
        assertTrue(m.find(), line);
        return m.group(1);
    }

    @Test
    void sslContextUsesTheConfiguredSessionTimeout() {
        long timeout = GRPCServer.buildSslContext(
                        pki.keyManagerFactory(pki.node("p")).getKeyManagers()[0],
                        TestPki.trustManager(pki.caCertificate()))
                .sessionContext()
                .getSessionTimeout();
        assertEquals(300, timeout);
    }

    private static RecordingObserver stream(ManagedChannel channel) {
        RecordingObserver observer = new RecordingObserver();
        FederatorServiceGrpc.newStub(channel).getKafkaConsumer(TopicRequest.getDefaultInstance(), observer);
        return observer;
    }

    private static final class RecordingObserver implements StreamObserver<KafkaByteBatch> {
        final AtomicInteger messages = new AtomicInteger();
        final AtomicReference<Throwable> error = new AtomicReference<>();

        @Override
        public void onNext(KafkaByteBatch value) {
            messages.incrementAndGet();
        }

        @Override
        public void onError(Throwable t) {
            error.set(t);
        }

        @Override
        public void onCompleted() {
            // streams in these tests do not complete
        }
    }

    /** Streams batches like the conductor: until the observer reports cancellation or onNext fails. */
    private static final class StreamingService extends FederatorServiceGrpc.FederatorServiceImplBase {
        final AtomicInteger calls = new AtomicInteger();
        final AtomicInteger terminatedLoops = new AtomicInteger();

        @Override
        public void getKafkaConsumer(TopicRequest request, StreamObserver<KafkaByteBatch> responseObserver) {
            calls.incrementAndGet();
            LimitedServerCallStreamObserver<KafkaByteBatch> observer =
                    new LimitedServerCallStreamObserver<>((ServerCallStreamObserver<KafkaByteBatch>) responseObserver);
            try {
                while (!observer.isCancelled()) {
                    observer.onNext(KafkaByteBatch.getDefaultInstance());
                    Thread.sleep(50);
                }
            } catch (StatusRuntimeException e) {
                // call terminated underneath
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                terminatedLoops.incrementAndGet();
            }
        }
    }
}
