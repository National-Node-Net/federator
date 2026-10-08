/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.common.policy;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record PolicyDecisionResponse(
        Boolean allow,
        @JsonProperty("row_filter") RowFilter rowFilter,
        @JsonProperty("policy_version") String policyVersion,
        List<String> reasons) {}
