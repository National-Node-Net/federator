/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.common.policy;

public class AllowAllPolicyDecisionClient implements PolicyDecisionClient {

    @Override
    public PolicyDecisionResponse evaluate(String decisionPath, PolicyDecisionRequest request) {
        return new PolicyDecisionResponse(true, null);
    }
}
