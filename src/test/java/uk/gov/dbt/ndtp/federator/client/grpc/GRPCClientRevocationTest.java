/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.client.grpc;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.ClientAuth;
import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import org.apache.kafka.common.utils.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import uk.gov.dbt.ndtp.federator.client.grpc.revocation.RevocationCheckedChannels;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationEngine;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationFailures;
import uk.gov.dbt.ndtp.federator.common.revocation.support.RevocationTestSupport;
import uk.gov.dbt.ndtp.federator.common.revocation.support.StubOcspResponder;
import uk.gov.dbt.ndtp.federator.common.revocation.support.StubOcspResponder.Answer;
import uk.gov.dbt.ndtp.federator.common.revocation.support.TestPki;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.common.utils.RedisUtil;
import uk.gov.dbt.ndtp.grpc.FederatorServiceGrpc;
import uk.gov.dbt.ndtp.grpc.KafkaByteBatch;
import uk.gov.dbt.ndtp.grpc.TopicRequest;
import uk.gov.dbt.ndtp.secure.agent.sources.kafka.sinks.KafkaSink;

/**
 * Consumer side end to end: real mTLS channels built by {@link RevocationCheckedChannels} to real Netty producers,
 * the consumer's {@link GRPCTopicClient} stream loop, and a stub OCSP responder following the Management Node
 * contract. Cache TTL is 2 s.
 */
class GRPCClientRevocationTest {

    private static final Duration TTL = Duration.ofSeconds(2);
    /** TTL + OCSP budget (1 s x 2 attempts) + scheduling slack. */
    private static final Duration DETECTION_BOUND = Duration.ofSeconds(6);

    @TempDir
    Path tempDir;

    private TestPki pki;
    private StubOcspResponder stub;
    private RevocationEngine engine;
    private final List<Server> servers = new ArrayList<>();
    private final List<ManagedChannel> channels = new ArrayList<>();

    @BeforeEach
    void setUp() {
        pki = new TestPki("Federation CA");
        stub = new StubOcspResponder(pki);
        Path consumerP12 = pki.writeP12(pki.node("consumer"), tempDir.resolve("consumer.p12"));
        Map<String, String> properties = new HashMap<>();
        properties.put("management.node.base.url", stub.baseUrl());
        properties.put("revocation.cache.ttl.seconds", String.valueOf(TTL.toSeconds()));
        properties.put("revocation.ocsp.requestTimeout", "1");
        properties.put("client.p12FilePath", consumerP12.toString());
        properties.put("client.p12Password", "changeit");
        properties.put("client.idleTimeout.secs", "1");
        RevocationTestSupport.initProperties(tempDir, properties);
        engine = RevocationEngine.build(
                "consumer",
                TestPki.trustManager(pki.caCertificate()),
                HttpClient.newHttpClient(),
                RevocationTestSupport.tokenService(),
                new SimpleMeterRegistry());
    }

    @AfterEach
    void tearDown() throws Exception {
        channels.forEach(ManagedChannel::shutdownNow);
        for (Server server : servers) {
            server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
        engine.close();
        stub.close();
        PropertyUtil.clear();
    }

    /** A producer that streams one batch every 30 ms, up to {@code limit} batches, then stays silent. */
    private Producer producer(String name, int limit) throws Exception {
        TestPki.Issued certificate = pki.node("localhost");
        StreamingProducer service = new StreamingProducer(limit);
        Server server = NettyServerBuilder.forPort(0)
                .sslContext(
                        GrpcSslContexts.configure(io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder.forServer(
                                        pki.keyManagerFactory(certificate)))
                                .trustManager(pki.caCertificate())
                                .clientAuth(ClientAuth.REQUIRE)
                                .build())
                .addService(service)
                .build()
                .start();
        servers.add(server);
        return new Producer(name, certificate, server, service);
    }

    private record Producer(String name, TestPki.Issued certificate, Server server, StreamingProducer service) {}

    private ManagedChannel channel(Producer producer) {
        ManagedChannel channel = RevocationCheckedChannels.build(
                "localhost", producer.server().getPort(), engine, UnaryOperator.identity());
        channels.add(channel);
        return channel;
    }

    private GRPCTopicClient topicClient(Producer producer) {
        return new GRPCTopicClient("consumer", "key", producer.name(), "federated", channel(producer));
    }

    @SuppressWarnings("unchecked")
    private static KafkaSink<Bytes, Bytes> countingSink(AtomicInteger written, Runnable onEach) {
        KafkaSink<Bytes, Bytes> sink = mock(KafkaSink.class);
        doAnswer(invocation -> {
                    written.incrementAndGet();
                    onEach.run();
                    return null;
                })
                .when(sink)
                .send(any());
        return sink;
    }

    private static TopicRequest request() {
        return TopicRequest.newBuilder().setTopic("topic").setOffset(0).build();
    }

    @Test
    void goodProducerIsStreamedAndWritten() throws Exception {
        Producer producer = producer("ProducerA", 5);
        AtomicInteger written = new AtomicInteger();
        try (MockedStatic<RedisUtil> redis = mockStatic(RedisUtil.class)) {
            redis.when(RedisUtil::getInstance).thenReturn(mock(RedisUtil.class));

            topicClient(producer).consumeMessagesAndSendOn(request(), countingSink(written, () -> {}));
        }
        assertEquals(5, written.get());
        assertEquals(1, stub.requests(), "handshake asks OCSP once, the call is served from the cache");
    }

    @Test
    void revokedProducerIsRejectedAtTheHandshakeAndNothingIsWritten() throws Exception {
        Producer producer = producer("ProducerA", 5);
        stub.answer(producer.certificate().certificate().getSerialNumber(), Answer.REVOKED);
        AtomicInteger written = new AtomicInteger();
        try (MockedStatic<RedisUtil> redis = mockStatic(RedisUtil.class)) {
            redis.when(RedisUtil::getInstance).thenReturn(mock(RedisUtil.class));

            RuntimeException failure = assertThrows(RuntimeException.class, () -> topicClient(producer)
                    .consumeMessagesAndSendOn(request(), countingSink(written, () -> {})));

            assertEquals(
                    RevocationFailures.Kind.PEER_CERTIFICATE_REJECTED,
                    RevocationFailures.classify(failure).orElseThrow());
        }
        assertEquals(0, written.get());
        assertEquals(0, producer.service().calls.get(), "no request reached the producer");
    }

    @Test
    void unknownProducerIsRejectedAtTheHandshake() throws Exception {
        Producer producer = producer("ProducerA", 5);
        stub.answer(producer.certificate().certificate().getSerialNumber(), Answer.UNKNOWN);
        try (MockedStatic<RedisUtil> redis = mockStatic(RedisUtil.class)) {
            redis.when(RedisUtil::getInstance).thenReturn(mock(RedisUtil.class));
            RuntimeException failure = assertThrows(RuntimeException.class, () -> topicClient(producer)
                    .consumeMessagesAndSendOn(request(), countingSink(new AtomicInteger(), () -> {})));
            assertEquals(
                    RevocationFailures.Kind.PEER_CERTIFICATE_REJECTED,
                    RevocationFailures.classify(failure).orElseThrow());
        }
    }

    @Test
    void revocationDuringAStreamStopsWritingAndClosesOnlyThatProducer() throws Exception {
        Producer revoked = producer("ProducerA", Integer.MAX_VALUE);
        Producer other = producer("ProducerB", Integer.MAX_VALUE);

        // another producer streamed in parallel on its own channel
        AtomicInteger otherMessages = new AtomicInteger();
        AtomicReference<Throwable> otherError = new AtomicReference<>();
        FederatorServiceGrpc.newStub(channel(other)).getKafkaConsumer(request(), new StreamObserver<>() {
            @Override
            public void onNext(KafkaByteBatch value) {
                otherMessages.incrementAndGet();
            }

            @Override
            public void onError(Throwable t) {
                otherError.set(t);
            }

            @Override
            public void onCompleted() {
                // the stream does not complete
            }
        });

        AtomicInteger written = new AtomicInteger();
        AtomicReference<Long> revokedAt = new AtomicReference<>();
        Runnable revokeAfterFiveMessages = () -> {
            if (written.get() == 5) {
                stub.answer(revoked.certificate().certificate().getSerialNumber(), Answer.REVOKED);
                revokedAt.set(System.nanoTime());
            }
        };
        ManagedChannel revokedChannel;
        RuntimeException failure;
        try (MockedStatic<RedisUtil> redis = mockStatic(RedisUtil.class)) {
            redis.when(RedisUtil::getInstance).thenReturn(mock(RedisUtil.class));
            GRPCTopicClient client = topicClient(revoked);
            revokedChannel = client.getChannel();

            failure = assertThrows(
                    RuntimeException.class,
                    () -> client.consumeMessagesAndSendOn(request(), countingSink(written, revokeAfterFiveMessages)));
        }
        Duration detection = Duration.ofNanos(System.nanoTime() - revokedAt.get());

        assertEquals(
                RevocationFailures.Kind.PEER_CERTIFICATE_REJECTED,
                RevocationFailures.classify(failure).orElseThrow());
        assertTrue(detection.compareTo(DETECTION_BOUND) <= 0, "cancelled after " + detection);
        assertTrue(revokedChannel.isShutdown(), "channel to the revoked producer shut down");
        int writtenAtCancel = written.get();
        await().atMost(Duration.ofSeconds(2))
                .until(() -> revoked.service().terminatedLoops.get() >= 1);
        assertEquals(writtenAtCancel, written.get(), "nothing written after the cancellation");

        int otherBefore = otherMessages.get();
        await().atMost(Duration.ofSeconds(3)).until(() -> otherMessages.get() > otherBefore);
        assertNull(otherError.get(), "the other producer is unaffected");
    }

    @Test
    void responderOutageDuringAStreamFailsClosed() throws Exception {
        Producer producer = producer("ProducerA", Integer.MAX_VALUE);
        AtomicInteger written = new AtomicInteger();
        Runnable outageAfterFiveMessages = () -> {
            if (written.get() == 5) {
                stub.httpStatus(503);
            }
        };
        try (MockedStatic<RedisUtil> redis = mockStatic(RedisUtil.class)) {
            redis.when(RedisUtil::getInstance).thenReturn(mock(RedisUtil.class));
            RuntimeException failure = assertThrows(RuntimeException.class, () -> topicClient(producer)
                    .consumeMessagesAndSendOn(request(), countingSink(written, outageAfterFiveMessages)));
            assertEquals(
                    RevocationFailures.Kind.PEER_STATUS_UNAVAILABLE,
                    RevocationFailures.classify(failure).orElseThrow());
        }
    }

    @Test
    void cachedStatusIsReusedAcrossChannels() throws Exception {
        Producer producer = producer("ProducerA", 2);
        try (MockedStatic<RedisUtil> redis = mockStatic(RedisUtil.class)) {
            RedisUtil redisUtil = mock(RedisUtil.class);
            redis.when(RedisUtil::getInstance).thenReturn(redisUtil);
            topicClient(producer).consumeMessagesAndSendOn(request(), countingSink(new AtomicInteger(), () -> {}));
            // OCSP requests seen by the time the second channel's first message is written (handshake + call done);
            // a later re-check of the still open stream may ask again once the 2 s TTL has passed
            AtomicInteger requestsAtSecondConnection = new AtomicInteger(-1);
            AtomicInteger secondWritten = new AtomicInteger();
            topicClient(producer).consumeMessagesAndSendOn(request(), countingSink(secondWritten, () -> {
                if (secondWritten.get() == 1) {
                    requestsAtSecondConnection.set(stub.requests());
                }
            }));
            org.mockito.Mockito.verify(redisUtil, org.mockito.Mockito.atLeastOnce())
                    .setOffset(anyString(), anyString(), anyLong());
            assertEquals(1, requestsAtSecondConnection.get(), "second connection served from the cache");
        }
    }

    /** Streams batches until cancelled or the limit is reached, like the producer's conductor. */
    private static final class StreamingProducer extends FederatorServiceGrpc.FederatorServiceImplBase {
        final AtomicInteger calls = new AtomicInteger();
        final AtomicInteger terminatedLoops = new AtomicInteger();
        private final int limit;

        StreamingProducer(int limit) {
            this.limit = limit;
        }

        @Override
        public void getKafkaConsumer(TopicRequest request, StreamObserver<KafkaByteBatch> responseObserver) {
            calls.incrementAndGet();
            ServerCallStreamObserver<KafkaByteBatch> observer =
                    (ServerCallStreamObserver<KafkaByteBatch>) responseObserver;
            try {
                for (int i = 0; i < limit && !observer.isCancelled(); i++) {
                    observer.onNext(KafkaByteBatch.newBuilder()
                            .setTopic(request.getTopic())
                            .setOffset(i)
                            .build());
                    Thread.sleep(30);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException e) {
                // cancelled by the consumer
            } finally {
                terminatedLoops.incrementAndGet();
            }
        }
    }
}
