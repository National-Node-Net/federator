/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.common.service.kafka;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.stream.Stream;
import org.apache.kafka.common.errors.InvalidTopicException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.dbt.ndtp.federator.common.model.dto.ConsumerDTO;
import uk.gov.dbt.ndtp.federator.common.model.dto.OrganisationDTO;
import uk.gov.dbt.ndtp.federator.common.model.dto.PolicyAttributeDTO;
import uk.gov.dbt.ndtp.federator.common.model.dto.ProducerConfigDTO;
import uk.gov.dbt.ndtp.federator.common.model.dto.ProducerDTO;
import uk.gov.dbt.ndtp.federator.common.model.dto.ProductConsumerDTO;
import uk.gov.dbt.ndtp.federator.common.model.dto.ProductDTO;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyAttribute;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionClient;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionRequest;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionResponse;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyInput;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyOrganisation;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyProducer;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyRequest;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyResource;
import uk.gov.dbt.ndtp.federator.common.policy.PolicySubject;
import uk.gov.dbt.ndtp.federator.common.policy.RowFilter;
import uk.gov.dbt.ndtp.federator.common.service.stream.CloseableFederatorStreamService;
import uk.gov.dbt.ndtp.federator.common.utils.ThreadUtil;
import uk.gov.dbt.ndtp.federator.server.conductor.MessageConductor;
import uk.gov.dbt.ndtp.federator.server.conductor.RdfMessageConductor;
import uk.gov.dbt.ndtp.federator.server.consumer.ClientTopicOffsets;
import uk.gov.dbt.ndtp.federator.server.grpc.GRPCContextKeys;
import uk.gov.dbt.ndtp.federator.server.interfaces.StreamObservable;
import uk.gov.dbt.ndtp.grpc.KafkaByteBatch;
import uk.gov.dbt.ndtp.grpc.TopicRequest;

public class KafkaStreamService extends CloseableFederatorStreamService<TopicRequest, KafkaByteBatch> {
    public static final Logger LOGGER = LoggerFactory.getLogger("KafkaStreamService");
    private static final String POLICY_ACTION_CONSUME = "consume";
    private static final String POLICY_SUBJECT_KIND_CLIENT = "client";
    private static final String POLICY_RESOURCE_KIND_PRODUCT = "product";

    private final boolean policyEnforcementEnabled;
    private final Set<String> sharedHeaders;
    private final PolicyDecisionClient policyDecisionClient;
    private final String policyDecisionPath;

    public KafkaStreamService(
            Set<String> sharedHeaders,
            PolicyDecisionClient policyDecisionClient,
            String policyDecisionPath,
            boolean policyEnforcementEnabled) {
        this.sharedHeaders = sharedHeaders;
        this.policyDecisionClient = policyDecisionClient;
        this.policyDecisionPath = policyDecisionPath;
        this.policyEnforcementEnabled = policyEnforcementEnabled;
    }

    private PolicyDecisionResponse evaluatePolicy(
            String consumerId,
            ConsumerDTO consumer,
            ProductDTO product,
            ProducerDTO producer,
            ProductConsumerDTO subscription,
            TopicRequest request) {
        List<PolicyAttribute> subjectAttributes =
                getPolicyAttributes(consumer == null ? null : consumer.getPolicyAttributes());

        PolicySubject subject = new PolicySubject(
                POLICY_SUBJECT_KIND_CLIENT,
                consumerId,
                Map.of(),
                subjectAttributes,
                getPolicyOrganisation(consumer == null ? null : consumer.getOrganisation()));

        PolicyResource policyResource = new PolicyResource(
                POLICY_RESOURCE_KIND_PRODUCT, getProductPolicyAttributes(product), getPolicyProducer(producer));

        Map<String, Object> subscriptionBody = subscription == null
                ? Map.of()
                : Map.of("policyAttributes", getPolicyAttributes(subscription.getPolicyAttributes()));

        Map<String, Object> requestBody = Map.of(
                "topic", request.getTopic(),
                "offset", request.getOffset(),
                "subscription", subscriptionBody);

        PolicyRequest policyRequestContext = new PolicyRequest(Map.of(), Map.of(), null, requestBody);

        PolicyInput policyInput = new PolicyInput(subject, POLICY_ACTION_CONSUME, policyResource, policyRequestContext);

        PolicyDecisionRequest policyRequest = new PolicyDecisionRequest(policyInput);

        PolicyDecisionResponse decision = policyDecisionClient.evaluate(policyDecisionPath, policyRequest);

        LOGGER.info(
                "Policy decision evaluated. Consumer: '{}', Topic: '{}', Allowed: '{}', Policy version: '{}', Reasons: '{}'",
                consumerId,
                request.getTopic(),
                decision.allow(),
                decision.policyVersion(),
                decision.reasons());

        return decision;
    }

    @Override
    public void streamToClient(
            TopicRequest request, StreamObservable<KafkaByteBatch> streamObservable, ExecutorService executorService)
            throws InvalidTopicException {
        String topic = request.getTopic();
        long offset = request.getOffset();
        String consumerId = GRPCContextKeys.CLIENT_ID.get();
        streamObservable.setOnCancelHandler(() -> LOGGER.info("Cancel called by client: {}", consumerId));
        ProducerConfigDTO producerConfigDTO = getProducerConfiguration();
        ProductDTO product = getProductForTopic(topic, producerConfigDTO);

        RowFilter rowFilter = null;

        if (policyEnforcementEnabled) {
            ConsumerDTO consumer = getConsumerForTopic(consumerId, topic, producerConfigDTO);
            ProducerDTO producer = getProducerForTopic(topic, producerConfigDTO);
            ProductConsumerDTO subscription = getSubscriptionForProduct(product, consumer);

            PolicyDecisionResponse policyDecisionResponse =
                    evaluatePolicy(consumerId, consumer, product, producer, subscription, request);

            if (!Boolean.TRUE.equals(policyDecisionResponse.allow())) {
                LOGGER.warn(
                        "Policy decision DENY [clientId={}, resource={}, action={}]",
                        consumerId,
                        topic,
                        POLICY_ACTION_CONSUME);

                throw new SecurityException("Request denied by policy");
            }

            LOGGER.info(
                    "Policy decision ALLOW [clientId={}, resource={}, action={}]",
                    consumerId,
                    topic,
                    POLICY_ACTION_CONSUME);

            rowFilter = policyDecisionResponse.rowFilter();

        } else {
            LOGGER.info("Policy enforcement disabled; bypassing policy decision");
        }

        streamObservable.setOnCancelHandler(() -> LOGGER.info("Cancel called by client: {}", consumerId));

        if (!hasConsumerAccessToTopic(consumerId, topic, producerConfigDTO)) {
            String errMsg = String.format("Topic (%s) is not valid for client (%s).", topic, consumerId);
            LOGGER.error(errMsg);
            throw new InvalidTopicException(errMsg);
        }

        ClientTopicOffsets topicData = new ClientTopicOffsets(consumerId, topic, offset);
        MessageConductor messageConductor =
                new RdfMessageConductor(topicData, streamObservable, rowFilter, this.sharedHeaders);
        messageConductors.add(messageConductor);

        List<Future<?>> futures = new ArrayList<>();
        futures.add(executorService.submit(messageConductor::processMessages));

        try {
            LOGGER.info(
                    "Awaiting TopicRequest finished for Client: {}, Topic: {}, Offset: {}",
                    consumerId,
                    topicData.getTopic(),
                    topicData.getOffset());

            ThreadUtil.awaitFutures(futures);

            LOGGER.info(
                    "Finished TopicRequest processed for Client: {}, Topic: {}, Offset: {}",
                    consumerId,
                    topicData.getTopic(),
                    topicData.getOffset());
        } finally {
            messageConductors.remove(messageConductor);
        }

        streamObservable.onCompleted();
    }

    /**
     * Determines whether a consumer has access to a given topic using the provided producer configuration.
     *
     * <p>Behavioral notes:
     * <ul>
     *   <li>Only the first producer in the configuration is considered (as per current business rule).</li>
     *   <li>Within that producer, products are filtered by an exact topic match.</li>
     *   <li>For matching products, consumers are checked for an idpClientId that matches the supplied consumerId (case-insensitive).</li>
     * </ul>
     *
     * <p>Nulls in the configuration or nested collections are handled defensively; if anything essential is missing, this method returns {@code false}.
     *
     * @param consumerId the consumer's IDP client id to check (case-insensitive)
     * @param topic the Kafka topic name to verify access for
     * @param producerConfigDTO the producer configuration source to inspect
     * @return {@code true} if a matching consumer is found for the topic under the first producer; otherwise {@code false}
     */
    private boolean hasConsumerAccessToTopic(String consumerId, String topic, ProducerConfigDTO producerConfigDTO) {
        if (producerConfigDTO == null || producerConfigDTO.getProducers() == null) {
            return false;
        }

        final String topicToMatch = topic == null ? null : topic.trim();

        return producerConfigDTO.getProducers().stream()
                .filter(Objects::nonNull)
                .flatMap(producer -> {
                    List<ProductDTO> products = producer.getProducts();
                    return products == null ? Stream.empty() : products.stream();
                })
                .filter(p -> p != null
                        && topicToMatch != null
                        && (p.getTopic() != null && p.getTopic().equalsIgnoreCase(topicToMatch)))
                .flatMap(p -> {
                    List<ConsumerDTO> consumers = p.getConsumers();
                    return consumers == null ? Stream.empty() : consumers.stream();
                })
                .anyMatch(c -> c != null
                        && c.getIdpClientId() != null
                        && c.getIdpClientId().equalsIgnoreCase(consumerId));
    }

    private ConsumerDTO getConsumerForTopic(String consumerId, String topic, ProducerConfigDTO producerConfigDTO) {

        if (producerConfigDTO == null || producerConfigDTO.getProducers() == null) {
            return null;
        }

        return producerConfigDTO.getProducers().stream()
                .filter(Objects::nonNull)
                .flatMap(producer -> producer.getProducts() == null ? Stream.empty() : producer.getProducts().stream())
                .filter(Objects::nonNull)
                .filter(product ->
                        product.getTopic() != null && product.getTopic().equalsIgnoreCase(topic))
                .flatMap(product -> product.getConsumers() == null ? Stream.empty() : product.getConsumers().stream())
                .filter(Objects::nonNull)
                .filter(consumer -> consumer.getIdpClientId() != null
                        && consumer.getIdpClientId().equalsIgnoreCase(consumerId))
                .findFirst()
                .orElse(null);
    }

    private ProductDTO getProductForTopic(String topic, ProducerConfigDTO producerConfigDTO) {
        if (producerConfigDTO == null || producerConfigDTO.getProducers() == null) {
            return null;
        }

        return producerConfigDTO.getProducers().stream()
                .filter(Objects::nonNull)
                .flatMap(producer -> producer.getProducts() == null ? Stream.empty() : producer.getProducts().stream())
                .filter(Objects::nonNull)
                .filter(product ->
                        product.getTopic() != null && product.getTopic().equalsIgnoreCase(topic))
                .findFirst()
                .orElse(null);
    }

    private List<PolicyAttribute> getPolicyAttributes(List<PolicyAttributeDTO> policyAttributes) {
        if (policyAttributes == null) {
            return List.of();
        }

        return policyAttributes.stream()
                .filter(Objects::nonNull)
                .filter(attribute -> attribute.getName() != null && attribute.getValue() != null)
                .map(attribute ->
                        new PolicyAttribute(attribute.getNamespace(), attribute.getName(), attribute.getValue()))
                .toList();
    }

    private PolicyProducer getPolicyProducer(ProducerDTO producer) {
        if (producer == null) {
            return null;
        }

        return new PolicyProducer(
                getPolicyAttributes(producer.getPolicyAttributes()), getPolicyOrganisation(producer.getOrganisation()));
    }

    private ProducerDTO getProducerForTopic(String topic, ProducerConfigDTO producerConfigDTO) {
        if (producerConfigDTO == null || producerConfigDTO.getProducers() == null) {
            return null;
        }

        return producerConfigDTO.getProducers().stream()
                .filter(Objects::nonNull)
                .filter(producer -> producer.getProducts() != null
                        && producer.getProducts().stream()
                                .filter(Objects::nonNull)
                                .anyMatch(product -> product.getTopic() != null
                                        && product.getTopic().equalsIgnoreCase(topic)))
                .findFirst()
                .orElse(null);
    }

    private ProductConsumerDTO getSubscriptionForProduct(ProductDTO product, ConsumerDTO consumer) {
        if (product == null || consumer == null || consumer.getId() == null || product.getConfigurations() == null) {
            return null;
        }

        return product.getConfigurations().stream()
                .filter(Objects::nonNull)
                .filter(configuration -> Objects.equals(configuration.getConsumerId(), consumer.getId()))
                .findFirst()
                .orElse(null);
    }

    private PolicyOrganisation getPolicyOrganisation(OrganisationDTO organisationDTO) {
        if (organisationDTO == null) {
            return null;
        }

        return new PolicyOrganisation(
                organisationDTO.getName(),
                organisationDTO.getKey(),
                getPolicyAttributes(organisationDTO.getPolicyAttributes()));
    }

    private List<PolicyAttribute> getProductPolicyAttributes(ProductDTO product) {
        if (product == null) {
            return List.of();
        }

        return getPolicyAttributes(product.getPolicyAttributes());
    }
}
