package uk.gov.dbt.ndtp.federator.common.policy;

public interface PolicyDecisionClient {

    PolicyDecisionResponse evaluate(PolicyDecisionRequest request);
}
