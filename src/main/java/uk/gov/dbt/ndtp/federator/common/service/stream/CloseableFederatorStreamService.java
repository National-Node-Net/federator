package uk.gov.dbt.ndtp.federator.common.service.stream;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import uk.gov.dbt.ndtp.federator.common.model.dto.AttributesDTO;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionClient;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionRequest;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyDecisionResponse;
import uk.gov.dbt.ndtp.federator.common.policy.PolicyInput;
import uk.gov.dbt.ndtp.federator.server.conductor.MessageConductor;

/**
 * An abstract class that implements both the {@link FederatorStreamService<R, T>} and {@link AutoCloseable}
 */
public abstract class CloseableFederatorStreamService<R, T> implements FederatorStreamService<R, T>, AutoCloseable {
    protected final List<MessageConductor> messageConductors = Collections.synchronizedList(new ArrayList<>());

    protected boolean isPolicyAllowed(
            PolicyDecisionClient policyDecisionClient,
            String policyDecisionPath,
            String consumerId,
            String resource,
            List<AttributesDTO> consumerAttributes) {

        Map<String, String> policyAttributes = consumerAttributes.stream()
                .filter(attribute -> attribute.getName() != null && attribute.getValue() != null)
                .collect(Collectors.toMap(
                        AttributesDTO::getName,
                        AttributesDTO::getValue,
                        (existingValue, replacementValue) -> replacementValue));

        PolicyInput policyInput = new PolicyInput(consumerId, null, resource, "consume", policyAttributes);

        PolicyDecisionRequest policyRequest = new PolicyDecisionRequest(policyInput);

        PolicyDecisionResponse policyDecisionResponse =
                policyDecisionClient.evaluate(policyDecisionPath, policyRequest);

        return Boolean.TRUE.equals(policyDecisionResponse.result());
    }

    @Override
    public void close() {
        for (MessageConductor messageConductor : messageConductors) {
            messageConductor.close();
        }

        messageConductors.clear();
    }
}
