/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.common.policy;

import java.util.Map;

public record PolicyRequest(
        Map<String, Object> headers, Map<String, Object> query, String path, Map<String, Object> body) {}
