package uk.gov.dbt.ndtp.federator;

import java.util.Set;
import java.util.concurrent.ExecutorService;
import org.apache.kafka.common.errors.InvalidTopicException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.dbt.ndtp.federator.common.policy.OpaPolicyDecisionClient;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionClient;
import uk.gov.dbt.ndtp.federator.common.service.file.FileStreamService;
import uk.gov.dbt.ndtp.federator.common.service.kafka.KafkaStreamService;
import uk.gov.dbt.ndtp.federator.common.service.stream.CloseableFederatorStreamService;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.common.utils.ThreadUtil;
import uk.gov.dbt.ndtp.federator.server.interfaces.StreamObservable;
import uk.gov.dbt.ndtp.grpc.FileStreamEvent;
import uk.gov.dbt.ndtp.grpc.FileStreamRequest;
import uk.gov.dbt.ndtp.grpc.KafkaByteBatch;
import uk.gov.dbt.ndtp.grpc.TopicRequest;

/**
 * Federator service that provides methods to get Kafka consumers and file consumers.
 */
public class FederatorService implements AutoCloseable {
    public static final Logger LOGGER = LoggerFactory.getLogger("FederatorService");

    private static final String POLICY_ENFORCEMENT_ENABLED_PROPERTY = "policy.enforcement.enabled";
    private static final String DEFAULT_POLICY_ENFORCEMENT_ENABLED = "false";

    private static final String OPA_URL_PROPERTY = "opa.url";
    private static final String OPA_DECISION_PATH_PROPERTY = "opa.decision-path";
    private static final String OPA_CONNECT_TIMEOUT_PROPERTY = "opa.connect-timeout";
    private static final String OPA_READ_TIMEOUT_PROPERTY = "opa.read-timeout";

    private static final String DEFAULT_OPA_URL = "http://localhost:8181";
    private static final String DEFAULT_OPA_DECISION_PATH = "/v1/data/producer/allow";
    private static final String DEFAULT_OPA_CONNECT_TIMEOUT = "5";
    private static final String DEFAULT_OPA_READ_TIMEOUT = "5";

    private static final ExecutorService THREADED_FILE_STREAM_SERVICE_EXECUTOR =
            ThreadUtil.threadExecutor("FileStreamService");
    private static final ExecutorService THREADED_KAFKA_STREAM_SERVICE_EXECUTOR =
            ThreadUtil.threadExecutor("KafkaStreamService");
    private final CloseableFederatorStreamService<TopicRequest, KafkaByteBatch> kafkaStreamService;
    private final CloseableFederatorStreamService<FileStreamRequest, FileStreamEvent> fileStreamService;

    public FederatorService(Set<String> sharedHeaders) {
        boolean policyEnforcementEnabled = PropertyUtil.getPropertyBooleanValue(
                POLICY_ENFORCEMENT_ENABLED_PROPERTY, DEFAULT_POLICY_ENFORCEMENT_ENABLED);

        PolicyDecisionClient policyDecisionClient = null;
        String opaDecisionPath = null;

        if (policyEnforcementEnabled) {
            String opaUrl = PropertyUtil.getPropertyValue(OPA_URL_PROPERTY, DEFAULT_OPA_URL);

            opaDecisionPath = PropertyUtil.getPropertyValue(OPA_DECISION_PATH_PROPERTY, DEFAULT_OPA_DECISION_PATH);

            int opaConnectTimeout = Integer.parseInt(
                    PropertyUtil.getPropertyValue(OPA_CONNECT_TIMEOUT_PROPERTY, DEFAULT_OPA_CONNECT_TIMEOUT));

            int opaReadTimeout = Integer.parseInt(
                    PropertyUtil.getPropertyValue(OPA_READ_TIMEOUT_PROPERTY, DEFAULT_OPA_READ_TIMEOUT));

            policyDecisionClient = new OpaPolicyDecisionClient(opaUrl, opaConnectTimeout, opaReadTimeout);
        }

        this.kafkaStreamService =
                new KafkaStreamService(sharedHeaders, policyDecisionClient, opaDecisionPath, policyEnforcementEnabled);

        this.fileStreamService = new FileStreamService();
    }

    /**
     * Gets a Kafka consumer for the given topic request and streams data to the provided stream observable.
     * @param request
     * @param streamObservable
     * @throws InvalidTopicException
     */
    public void getKafkaConsumer(TopicRequest request, StreamObservable<KafkaByteBatch> streamObservable)
            throws InvalidTopicException {
        kafkaStreamService.streamToClient(request, streamObservable, THREADED_KAFKA_STREAM_SERVICE_EXECUTOR);
    }

    /**
     * Gets a file consumer for the given file stream request and streams data to the provided stream observable.
     * @param request
     * @param streamObservable
     */
    public void getFileConsumer(FileStreamRequest request, StreamObservable<FileStreamEvent> streamObservable) {
        fileStreamService.streamToClient(request, streamObservable, THREADED_FILE_STREAM_SERVICE_EXECUTOR);
    }

    @Override
    public void close() {
        fileStreamService.close();
        kafkaStreamService.close();
        THREADED_FILE_STREAM_SERVICE_EXECUTOR.shutdown();
        THREADED_KAFKA_STREAM_SERVICE_EXECUTOR.shutdown();
    }
}
