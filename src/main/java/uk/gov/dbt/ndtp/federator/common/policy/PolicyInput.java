package uk.gov.dbt.ndtp.federator.common.policy;

import java.util.Map;

public record PolicyInput(
        String clientId, String organisation, String resource, String action, Map<String, String> attributes) {}
