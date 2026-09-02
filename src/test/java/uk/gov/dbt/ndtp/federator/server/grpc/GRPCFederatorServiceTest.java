package uk.gov.dbt.ndtp.federator.server.grpc;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import io.grpc.Status;
import io.grpc.stub.ServerCallStreamObserver;
import org.junit.jupiter.api.Test;
import uk.gov.dbt.ndtp.federator.FederatorService;
import uk.gov.dbt.ndtp.grpc.FileStreamEvent;
import uk.gov.dbt.ndtp.grpc.FileStreamRequest;

class GRPCFederatorServiceTest {

    @Test
    void getFilesStream_whenPolicyDenies_returnsPermissionDenied() {
        FederatorService federator = mock(FederatorService.class);
        GRPCFederatorService grpcService = new GRPCFederatorService(federator);

        FileStreamRequest request =
                FileStreamRequest.newBuilder().setTopic("test-topic").build();

        ServerCallStreamObserver<FileStreamEvent> responseObserver = mock(ServerCallStreamObserver.class);

        doThrow(new SecurityException("Request denied by policy"))
                .when(federator)
                .getFileConsumer(org.mockito.ArgumentMatchers.eq(request), org.mockito.ArgumentMatchers.any());

        grpcService.getFilesStream(request, responseObserver);

        verify(responseObserver)
                .onError(org.mockito.ArgumentMatchers.argThat(
                        error -> Status.fromThrowable(error).getCode() == Status.Code.PERMISSION_DENIED));
    }
}
