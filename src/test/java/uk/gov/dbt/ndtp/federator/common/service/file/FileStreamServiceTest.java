// SPDX-License-Identifier: Apache-2.0
package uk.gov.dbt.ndtp.federator.common.service.file;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import io.grpc.Context;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.dbt.ndtp.federator.common.model.dto.ProducerConfigDTO;
import uk.gov.dbt.ndtp.federator.common.policy.AllowAllPolicyDecisionClient;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionClient;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionResponse;
import uk.gov.dbt.ndtp.federator.common.service.config.ProducerConfigService;
import uk.gov.dbt.ndtp.federator.common.utils.ProducerConsumerConfigServiceFactory;
import uk.gov.dbt.ndtp.federator.server.conductor.FileConductor;
import uk.gov.dbt.ndtp.federator.server.grpc.GRPCContextKeys;
import uk.gov.dbt.ndtp.federator.server.interfaces.StreamObservable;
import uk.gov.dbt.ndtp.grpc.FileStreamEvent;
import uk.gov.dbt.ndtp.grpc.FileStreamRequest;

class FileStreamServiceTest {

    @Test
    void test_streamToClient_invokesConductorAndCompletes() {
        FileStreamService cut = new FileStreamService(new AllowAllPolicyDecisionClient());

        StreamObservable<FileStreamEvent> observer = mock(StreamObservable.class);

        ExecutorService executorService = mock(ExecutorService.class);
        Future mockFuture = mock(Future.class);

        when(executorService.submit(any(Runnable.class))).thenReturn(mockFuture);

        FileStreamRequest req = FileStreamRequest.newBuilder()
                .setTopic("files-topic")
                .setStartSequenceId(0L)
                .build();

        try (MockedConstruction<FileConductor> mocked = Mockito.mockConstruction(
                        FileConductor.class,
                        (mock, ctx) -> doNothing().when(mock).close());
                MockedStatic<ProducerConsumerConfigServiceFactory> mockedFactory =
                        Mockito.mockStatic(ProducerConsumerConfigServiceFactory.class)) {

            // Mock config service to avoid hitting PropertyUtil in tests
            ProducerConfigService mockConfigService = mock(ProducerConfigService.class);
            ProducerConfigDTO emptyCfg =
                    ProducerConfigDTO.builder().producers(java.util.List.of()).build();
            mockedFactory
                    .when(ProducerConsumerConfigServiceFactory::getProducerConfigService)
                    .thenReturn(mockConfigService);
            when(mockConfigService.getProducerConfiguration()).thenReturn(emptyCfg);

            // Put client id into gRPC Context so service can read it
            Context grpcCtx = Context.current().withValue(GRPCContextKeys.CLIENT_ID, "client-xyz");
            Context prev = grpcCtx.attach();
            try {
                cut.streamToClient(req, observer, executorService);
            } finally {
                grpcCtx.detach(prev);
            }

            // One FileConductor constructed
            assertEquals(1, mocked.constructed().size());

            try {
                verify(mockFuture, times(1)).get();
            } catch (InterruptedException | ExecutionException ignored) {
                // ignored
            }

            // Cancel handler is set and onCompleted called
            verify(observer, times(1)).setOnCancelHandler(any());
            verify(observer, times(1)).onCompleted();
        }
    }

    @Test
    void streamToClient_whenPolicyAllows_continuesProcessing() {
        FileStreamService fileStreamService = new FileStreamService(new AllowAllPolicyDecisionClient());

        StreamObservable<FileStreamEvent> observer = mock(StreamObservable.class);
        ExecutorService executorService = mock(ExecutorService.class);
        Future mockFuture = mock(Future.class);

        when(executorService.submit(any(Runnable.class))).thenReturn(mockFuture);

        FileStreamRequest fileRequest = FileStreamRequest.newBuilder()
                .setTopic("test-topic")
                .setStartSequenceId(0L)
                .build();

        try (MockedConstruction<FileConductor> mocked = Mockito.mockConstruction(
                        FileConductor.class,
                        (mock, context) -> doNothing().when(mock).close());
                MockedStatic<ProducerConsumerConfigServiceFactory> mockedFactory =
                        Mockito.mockStatic(ProducerConsumerConfigServiceFactory.class)) {

            ProducerConfigService mockConfigService = mock(ProducerConfigService.class);

            ProducerConfigDTO emptyConfig =
                    ProducerConfigDTO.builder().producers(java.util.List.of()).build();

            mockedFactory
                    .when(ProducerConsumerConfigServiceFactory::getProducerConfigService)
                    .thenReturn(mockConfigService);

            when(mockConfigService.getProducerConfiguration()).thenReturn(emptyConfig);

            Context grpcContext = Context.current().withValue(GRPCContextKeys.CLIENT_ID, "client-xyz");

            Context previousContext = grpcContext.attach();

            try {
                fileStreamService.streamToClient(fileRequest, observer, executorService);
            } finally {
                grpcContext.detach(previousContext);
            }

            assertEquals(1, mocked.constructed().size());
            verify(observer, times(1)).onCompleted();
        }
    }

    @Test
    void streamToClient_whenPolicyDenies_throwsSecurityException() {
        PolicyDecisionClient denyPolicyDecisionClient = request -> new PolicyDecisionResponse(false);
        FileStreamService fileStreamService = new FileStreamService(denyPolicyDecisionClient);
        FileStreamRequest fileRequest =
                FileStreamRequest.newBuilder().setTopic("test-topic").build();

        StreamObservable<FileStreamEvent> observer = mock(StreamObservable.class);
        ExecutorService executorService = mock(ExecutorService.class);

        assertThrows(
                SecurityException.class,
                () -> fileStreamService.streamToClient(fileRequest, observer, executorService));
    }
}
