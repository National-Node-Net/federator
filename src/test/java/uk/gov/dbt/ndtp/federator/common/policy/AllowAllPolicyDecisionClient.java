package uk.gov.dbt.ndtp.federator.common.policy;

public class AllowAllPolicyDecisionClient implements PolicyDecisionClient {

    @Override
    public PolicyDecisionResponse evaluate(PolicyDecisionRequest request) {
        return new PolicyDecisionResponse(true);
    }
}
