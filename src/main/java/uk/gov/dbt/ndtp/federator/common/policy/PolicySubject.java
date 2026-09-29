/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.common.policy;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

public record PolicySubject(
        String kind,
        @JsonProperty("user_id") String userId,
        Map<String, Object> token,
        List<PolicyAttribute> attributes,
        PolicyOrganisation organisation) {}
