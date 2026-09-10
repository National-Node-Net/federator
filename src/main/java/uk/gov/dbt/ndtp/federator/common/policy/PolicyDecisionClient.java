/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.common.policy;

/**
 * Client abstraction for evaluating policy decisions against a policy decision point.
 */
public interface PolicyDecisionClient {

    /**
     * Evaluates a policy decision request.
     *
     * @param decisionPath the policy decision endpoint path
     * @param request the policy decision request
     * @return the policy decision response
     */
    PolicyDecisionResponse evaluate(String decisionPath, PolicyDecisionRequest request);
}
