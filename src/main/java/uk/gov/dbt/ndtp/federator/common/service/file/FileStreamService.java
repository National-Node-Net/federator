package uk.gov.dbt.ndtp.federator.common.service.file;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.dbt.ndtp.federator.common.model.dto.AttributesDTO;
import uk.gov.dbt.ndtp.federator.common.model.dto.ProducerConfigDTO;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionClient;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionRequest;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionResponse;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyInput;
import uk.gov.dbt.ndtp.federator.common.service.stream.CloseableFederatorStreamService;
import uk.gov.dbt.ndtp.federator.common.utils.ThreadUtil;
import uk.gov.dbt.ndtp.federator.server.conductor.FileConductor;
import uk.gov.dbt.ndtp.federator.server.conductor.MessageConductor;
import uk.gov.dbt.ndtp.federator.server.consumer.ClientTopicOffsets;
import uk.gov.dbt.ndtp.federator.server.grpc.GRPCContextKeys;
import uk.gov.dbt.ndtp.federator.server.interfaces.StreamObservable;
import uk.gov.dbt.ndtp.grpc.FileStreamEvent;
import uk.gov.dbt.ndtp.grpc.FileStreamRequest;

public class FileStreamService extends CloseableFederatorStreamService<FileStreamRequest, FileStreamEvent> {
    private static final Logger LOGGER = LoggerFactory.getLogger(FileStreamService.class);
    private final PolicyDecisionClient policyDecisionClient;
    private final String policyDecisionPath;

    public FileStreamService(PolicyDecisionClient policyDecisionClient, String policyDecisionPath) {
        this.policyDecisionClient = policyDecisionClient;
        this.policyDecisionPath = policyDecisionPath;
    }

    @Override
    public void streamToClient(
            FileStreamRequest fileRequest,
            StreamObservable<FileStreamEvent> streamObservable,
            ExecutorService executorService) {
        long offset = fileRequest.getStartSequenceId();
        String consumerId = GRPCContextKeys.CLIENT_ID.get();
        streamObservable.setOnCancelHandler(() -> LOGGER.info("Cancel called by client: {}", consumerId));
        String topic = fileRequest.getTopic();

        ProducerConfigDTO producerConfigDTO = getProducerConfiguration();

        List<AttributesDTO> consumerAttributes = getFilterAttributesForConsumer(consumerId, topic, producerConfigDTO);

        Map<String, String> policyAttributes = consumerAttributes.stream()
                .filter(attribute -> attribute.getName() != null && attribute.getValue() != null)
                .collect(Collectors.toMap(
                        AttributesDTO::getName,
                        AttributesDTO::getValue,
                        (existingValue, replacementValue) -> replacementValue));

        PolicyInput policyInput = new PolicyInput(consumerId, null, topic, "consume", policyAttributes);

        PolicyDecisionRequest policyRequest = new PolicyDecisionRequest(policyInput);
        PolicyDecisionResponse policyDecisionResponse =
                policyDecisionClient.evaluate(policyDecisionPath, policyRequest);

        if (!Boolean.TRUE.equals(policyDecisionResponse.result())) {
            LOGGER.warn("Policy decision DENY [clientId={}, resource={}, action=consume]", consumerId, topic);

            throw new SecurityException("Request denied by policy");
        }
        LOGGER.info("Policy decision ALLOW [clientId={}, resource={}, action=consume]", consumerId, topic);

        ClientTopicOffsets topicData = new ClientTopicOffsets(consumerId, fileRequest.getTopic(), offset);
        MessageConductor messageConductor = new FileConductor(topicData, streamObservable, consumerAttributes);
        messageConductors.add(messageConductor);

        List<Future<?>> futures = new ArrayList<>();
        futures.add(executorService.submit(messageConductor::processMessages));

        try {
            LOGGER.info(
                    "Awaiting FileStreamRequest finished for Client: {}, Topic: {}, Offset: {}",
                    consumerId,
                    topicData.getTopic(),
                    topicData.getOffset());

            ThreadUtil.awaitFutures(futures);

            LOGGER.info(
                    "Finished FileStreamRequest processed for Client: {}, Topic: {}, Offset: {}",
                    consumerId,
                    topicData.getTopic(),
                    topicData.getOffset());
        } finally {
            messageConductors.remove(messageConductor);
        }

        streamObservable.onCompleted();
    }
}
