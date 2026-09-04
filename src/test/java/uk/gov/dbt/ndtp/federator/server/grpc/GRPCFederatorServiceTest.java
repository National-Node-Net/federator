package uk.gov.dbt.ndtp.federator.server.grpc;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import io.grpc.Status;
import io.grpc.stub.ServerCallStreamObserver;
import org.junit.jupiter.api.Test;
import uk.gov.dbt.ndtp.federator.FederatorService;
import uk.gov.dbt.ndtp.grpc.KafkaByteBatch;
import uk.gov.dbt.ndtp.grpc.TopicRequest;

class GRPCFederatorServiceTest {

    @Test
    void getKafkaConsumer_whenPolicyDenies_returnsPermissionDenied() {
        FederatorService federator = mock(FederatorService.class);
        GRPCFederatorService grpcService = new GRPCFederatorService(federator);

        TopicRequest request = TopicRequest.newBuilder().setTopic("test-topic").build();

        ServerCallStreamObserver<KafkaByteBatch> responseObserver = mock(ServerCallStreamObserver.class);

        doThrow(new SecurityException("Request denied by policy"))
                .when(federator)
                .getKafkaConsumer(org.mockito.ArgumentMatchers.eq(request), org.mockito.ArgumentMatchers.any());

        grpcService.getKafkaConsumer(request, responseObserver);

        verify(responseObserver)
                .onError(org.mockito.ArgumentMatchers.argThat(
                        error -> Status.fromThrowable(error).getCode() == Status.Code.PERMISSION_DENIED));
    }
}
