package uk.gov.dbt.ndtp.federator.common.policy;

import java.util.Map;

public record PolicyDecisionResponse(Boolean result, Map<String, String> attributes) {}
