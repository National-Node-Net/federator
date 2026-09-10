/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.common.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class OpaPolicyDecisionClient implements PolicyDecisionClient {

    private final String opaUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration readTimeout;

    public OpaPolicyDecisionClient(String opaUrl, int connectTimeoutSeconds, int readTimeoutSeconds) {

        this.opaUrl = opaUrl;

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(connectTimeoutSeconds))
                .build();

        this.objectMapper = new ObjectMapper();
        this.readTimeout = Duration.ofSeconds(readTimeoutSeconds);
    }

    @Override
    public PolicyDecisionResponse evaluate(String decisionPath, PolicyDecisionRequest request) {
        try {
            String requestBody = objectMapper.writeValueAsString(request);

            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(opaUrl + decisionPath))
                    .timeout(readTimeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                return new PolicyDecisionResponse(false, null);
            }

            JsonNode root = objectMapper.readTree(response.body());
            JsonNode result = root.get("result");

            if (result == null || result.isNull()) {
                return new PolicyDecisionResponse(false, null);
            }

            PolicyDecisionResponse decisionResponse = objectMapper.treeToValue(result, PolicyDecisionResponse.class);

            if (decisionResponse == null || !Boolean.TRUE.equals(decisionResponse.result())) {
                return new PolicyDecisionResponse(false, null);
            }

            return decisionResponse;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new PolicyDecisionResponse(false, null);
        } catch (Exception e) {
            return new PolicyDecisionResponse(false, null);
        }
    }
}
