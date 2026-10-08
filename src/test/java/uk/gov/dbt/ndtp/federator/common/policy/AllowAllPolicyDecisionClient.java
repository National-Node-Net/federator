/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.common.policy;

import java.util.List;

public class AllowAllPolicyDecisionClient implements PolicyDecisionClient {

    @Override
    public PolicyDecisionResponse evaluate(String decisionPath, PolicyDecisionRequest request) {
        return new PolicyDecisionResponse(true, null, null, List.of());
    }
}
