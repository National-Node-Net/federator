/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.metrics;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import lombok.extern.slf4j.Slf4j;
import uk.gov.dbt.ndtp.federator.common.annotations.ExcludeFromJacocoGeneratedReport;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;

/**
 * Process-wide Prometheus meter registry and a small HTTP endpoint that serves it at {@code GET /metrics}.
 * <p>
 * Configuration: {@code metrics.enabled} (default {@code true}) and {@code metrics.port} (default {@code 9464}).
 */
@Slf4j
public final class MetricsServer implements AutoCloseable {

    public static final String METRICS_ENABLED = "metrics.enabled";
    public static final String METRICS_PORT = "metrics.port";
    public static final String DEFAULT_PORT = "9464";
    static final String PATH = "/metrics";
    static final String CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";

    private static final PrometheusMeterRegistry REGISTRY = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

    private final HttpServer server;
    private final ExecutorService executor;

    private MetricsServer(HttpServer server, ExecutorService executor) {
        this.server = server;
        this.executor = executor;
    }

    /**
     * @return the registry all Federator metrics are registered with
     */
    public static MeterRegistry registry() {
        return REGISTRY;
    }

    /**
     * Starts the endpoint when {@code metrics.enabled} is true.
     *
     * @return the running server, or null when metrics are disabled or the port cannot be bound
     */
    @ExcludeFromJacocoGeneratedReport
    public static MetricsServer startIfEnabled() {
        if (!PropertyUtil.getPropertyBooleanValue(METRICS_ENABLED, "true")) {
            log.info("Metrics endpoint disabled ({}=false)", METRICS_ENABLED);
            return null;
        }
        int port = PropertyUtil.getPropertyIntValue(METRICS_PORT, DEFAULT_PORT);
        try {
            return start(port);
        } catch (IOException e) {
            log.error("Metrics endpoint could not be started on port {}", port, e);
            return null;
        }
    }

    /**
     * Starts the endpoint on a port; {@code 0} picks a free port.
     */
    public static MetricsServer start(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext(PATH, MetricsServer::handle);
        ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "metrics-http");
            thread.setDaemon(true);
            return thread;
        });
        server.setExecutor(executor);
        server.start();
        log.info(
                "Metrics endpoint listening on port {} at {}",
                server.getAddress().getPort(),
                PATH);
        return new MetricsServer(server, executor);
    }

    public int port() {
        return server.getAddress().getPort();
    }

    private static void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            if (!"GET".equals(exchange.getRequestMethod())
                    || !PATH.equals(exchange.getRequestURI().getPath())) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            byte[] body = REGISTRY.scrape().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", CONTENT_TYPE);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }
}
