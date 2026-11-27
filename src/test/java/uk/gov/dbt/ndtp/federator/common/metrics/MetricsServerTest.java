/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.metrics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.micrometer.core.instrument.Counter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;

class MetricsServerTest {

    @Test
    void servesPrometheusMetrics() throws Exception {
        Counter.builder("federator.test.counter")
                .register(MetricsServer.registry())
                .increment();
        try (MetricsServer server = MetricsServer.start(0)) {
            HttpClient client = HttpClient.newHttpClient();
            URI base = URI.create("http://127.0.0.1:" + server.port());

            HttpResponse<String> metrics = client.send(
                    HttpRequest.newBuilder(base.resolve("/metrics")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, metrics.statusCode());
            assertTrue(metrics.body().contains("federator_test_counter_total"));
            assertTrue(metrics.headers().firstValue("Content-Type").orElse("").startsWith("text/plain"));

            HttpResponse<String> other = client.send(
                    HttpRequest.newBuilder(base.resolve("/metrics/other")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(404, other.statusCode());

            HttpResponse<String> post = client.send(
                    HttpRequest.newBuilder(base.resolve("/metrics"))
                            .POST(HttpRequest.BodyPublishers.noBody())
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(404, post.statusCode());
        }
    }
}
