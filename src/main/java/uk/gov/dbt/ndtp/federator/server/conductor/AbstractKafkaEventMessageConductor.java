// SPDX-License-Identifier: Apache-2.0
// Originally developed by Telicent Ltd.; subsequently adapted, enhanced, and maintained by the National Digital Twin
// Programme.

/*
 *  Copyright (c) Telicent Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Modifications made by the National Digital Twin Programme (NDTP)
 *  © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme
 *  and is legally attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.server.conductor;

import static uk.gov.dbt.ndtp.federator.common.utils.HeaderUtils.*;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.dbt.ndtp.federator.common.model.dto.AttributesDTO;
import uk.gov.dbt.ndtp.federator.common.policy.RowFilter;
import uk.gov.dbt.ndtp.federator.common.policy.RowFilterComparison;
import uk.gov.dbt.ndtp.federator.common.policy.RowFilterGroup;
import uk.gov.dbt.ndtp.federator.exceptions.MessageProcessingException;
import uk.gov.dbt.ndtp.federator.server.consumer.MessageConsumer;
import uk.gov.dbt.ndtp.federator.server.processor.MessageProcessor;
import uk.gov.dbt.ndtp.secure.agent.sources.Header;
import uk.gov.dbt.ndtp.secure.agent.sources.kafka.KafkaEvent;

/**
 * Abstract representation of a message processor for Secure Agent Kafka Events
 * (with Key/Event)
 *
 * @param <K>   the datatype of the event's key
 * @param <V> the underlying datatype for the event
 */
public abstract class AbstractKafkaEventMessageConductor<K, V>
        extends AbstractMessageConductor<KafkaEvent<?, ?>, KafkaEvent<K, V>> {

    public static final Logger LOGGER = LoggerFactory.getLogger("AbstractKafkaEventMessageProcessor");
    protected final RowFilter rowFilter;

    AbstractKafkaEventMessageConductor(
            MessageConsumer<KafkaEvent<K, V>> consumer,
            MessageProcessor<KafkaEvent<K, V>> postProcessor,
            RowFilter rowFilter) {
        super(consumer, postProcessor, List.of());
        this.rowFilter = rowFilter;
    }

    AbstractKafkaEventMessageConductor(
            MessageConsumer<KafkaEvent<K, V>> consumer,
            MessageProcessor<KafkaEvent<K, V>> postProcessor,
            List<AttributesDTO> filterAttributes) {
        super(consumer, postProcessor, filterAttributes);
        this.rowFilter = null;
    }

    @Override
    public void processMessages() throws MessageProcessingException {
        try {
            while (continueProcessing()) {
                processMessage();
            }
        } catch (Exception e) {
            throw new MessageProcessingException(e);
        } finally {
            super.close();
        }
    }

    @Override
    public void processMessage() {
        LOGGER.debug("Before messageConsumer.getNextMessage() .... ");
        KafkaEvent<K, V> kafkaEvent = messageConsumer.getNextMessage();
        LOGGER.debug("After messageConsumer.getNextMessage() .... ");
        if (kafkaEvent == null) {
            LOGGER.debug("Timed out waiting for Consumer to return more events, continue waiting");
        } else {
            long offset = kafkaEvent.getConsumerRecord().offset();
            K key = kafkaEvent.key();

            if (isEventAllowed(kafkaEvent)) {
                LOGGER.debug("Before messageProcessor.process(kafkaEvent) .... ");
                messageProcessor.process(kafkaEvent);
                String headers = kafkaEvent.headers().map(Header::toString).collect(Collectors.joining(","));
                LOGGER.info("Processed message. Offset: '{}'. Key: '{}'. Kafka Header: '{}'", offset, key, headers);
            } else {
                LOGGER.warn("Filtering out message due to policy filter. Offset: '{}'. Key: '{}'", offset, key);
            }
        }
    }

    /**
     * Determines whether the given Kafka event should be allowed through.
     *
     * <p>If a row filter is configured, it is evaluated against the message's
     * security-label attributes. Otherwise, the legacy attribute filtering
     * behaviour is used.
     */
    protected boolean isEventAllowed(KafkaEvent<K, V> kafkaEvent) {
        String secLabel = getSecurityLabelFromHeaders(kafkaEvent.headers());
        LOGGER.debug("Processing Message. SecLabel for message {}", secLabel);

        Map<String, String> headerMap = getMapFromSecurityLabel(secLabel);

        if (rowFilter != null) {
            LOGGER.debug("Headers map: {} , Row filter: {}", headerMap, rowFilter);
            return evaluateRowFilter(rowFilter, headerMap);
        }

        // Legacy filtering path used by FileConductor
        if (filterAttributes == null || filterAttributes.isEmpty()) {
            return true;
        }

        LOGGER.debug("Headers map: {} , Filtering attributes: {}", headerMap, filterAttributes);

        for (AttributesDTO attr : filterAttributes) {
            if (attr == null) {
                continue;
            }

            String name = attr.getName();
            String expectedValue = attr.getValue();

            if (name == null || expectedValue == null) {
                return false;
            }

            String actual = headerMap.get(name.toUpperCase(Locale.ROOT));

            if (actual == null) {
                LOGGER.info("Header '{}' missing for required attribute '{}'", name, expectedValue);
                return false;
            }

            if (!actual.equalsIgnoreCase(expectedValue)) {
                return false;
            }
        }

        return true;
    }

    private boolean evaluateRowFilter(RowFilter filter, Map<String, String> headerMap) {
        if (filter instanceof RowFilterComparison comparison) {
            return evaluateComparison(comparison, headerMap);
        }
        if (filter instanceof RowFilterGroup group) {
            return evaluateGroup(group, headerMap);
        }
        return false;
    }

    private boolean evaluateComparison(RowFilterComparison comparison, Map<String, String> headerMap) {
        if (comparison.attribute() == null || comparison.values() == null) {
            return false;
        }

        String actualValue = headerMap.get(comparison.attribute().toUpperCase(Locale.ROOT));

        if (actualValue == null) {
            return false;
        }

        return comparison.values().stream().map(String::valueOf).anyMatch(actualValue::equalsIgnoreCase);
    }

    private boolean evaluateGroup(RowFilterGroup group, Map<String, String> headerMap) {
        if (group.combinator() == null || group.nodes() == null) {
            return false;
        }

        if ("and".equalsIgnoreCase(group.combinator())) {
            return group.nodes().stream().allMatch(node -> evaluateRowFilter(node, headerMap));
        }

        if ("or".equalsIgnoreCase(group.combinator())) {
            return group.nodes().stream().anyMatch(node -> evaluateRowFilter(node, headerMap));
        }

        return false;
    }
}
