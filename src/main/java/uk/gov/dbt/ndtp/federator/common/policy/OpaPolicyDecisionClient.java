package uk.gov.dbt.ndtp.federator.common.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class OpaPolicyDecisionClient implements PolicyDecisionClient {

    private final String opaUrl;
    private final String decisionPath;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration readTimeout;

    public OpaPolicyDecisionClient(
            String opaUrl, String decisionPath, int connectTimeoutSeconds, int readTimeoutSeconds) {

        this.opaUrl = opaUrl;
        this.decisionPath = decisionPath;

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(connectTimeoutSeconds))
                .build();

        this.objectMapper = new ObjectMapper();
        this.readTimeout = Duration.ofSeconds(readTimeoutSeconds);
    }

    @Override
    public PolicyDecisionResponse evaluate(PolicyDecisionRequest request) {
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
                return new PolicyDecisionResponse(false);
            }

            PolicyDecisionResponse decisionResponse =
                    objectMapper.readValue(response.body(), PolicyDecisionResponse.class);

            if (decisionResponse == null || !Boolean.TRUE.equals(decisionResponse.result())) {
                return new PolicyDecisionResponse(false);
            }

            return decisionResponse;

        } catch (Exception e) {
            return new PolicyDecisionResponse(false);
        }
    }
}
