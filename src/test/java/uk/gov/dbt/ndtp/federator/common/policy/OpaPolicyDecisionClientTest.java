/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.common.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class OpaPolicyDecisionClientTest {

    private static final String OPA_TEST_PATH = "/v1/data";
    private static final String OPA_NULL_RESPONSE_PATH = "/v1/data/test/allow";
    private static final int CONNECT_TIMEOUT = 5;
    private static final int READ_TIMEOUT = 5;

    @Test
    void returnsAllowWhenOpaReturnsTrue() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);

        server.createContext(OPA_TEST_PATH, exchange -> {
            byte[] response =
                    """
            {"result":{"allow":true,"row_filter":{"type":"comparison","attribute":"classification", "values":["OFFICIAL"]},"policy_version":"test-policy/1.0.0","reasons":["access.granted"]}}
            """
                            .getBytes(StandardCharsets.UTF_8);

            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.start();

        try {
            OpaPolicyDecisionClient client = createClient(server.getAddress().getPort());

            PolicyDecisionResponse response = client.evaluate(OPA_TEST_PATH, createRequest());

            assertEquals(Boolean.TRUE, response.allow());

            assertTrue(response.rowFilter() instanceof RowFilterComparison);

            RowFilterComparison rowFilter = (RowFilterComparison) response.rowFilter();

            assertEquals("classification", rowFilter.attribute());
            assertEquals(List.of("OFFICIAL"), rowFilter.values());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsDenyWhenOpaReturnsFalse() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);

        server.createContext(OPA_TEST_PATH, exchange -> {
            byte[] response =
                    """
                {"result":{"allow":false,"row_filter":null,"policy_version":"test-policy/1.0.0","reasons":["access.denied"]}}
                """
                            .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.start();

        try {
            OpaPolicyDecisionClient client = createClient(server.getAddress().getPort());

            PolicyDecisionResponse response = client.evaluate(OPA_TEST_PATH, createRequest());

            assertEquals(Boolean.FALSE, response.allow());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsDenyWhenOpaReturnsServerError() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);

        server.createContext(OPA_TEST_PATH, exchange -> {
            exchange.sendResponseHeaders(500, -1);
            exchange.close();
        });

        server.start();

        try {
            OpaPolicyDecisionClient client = createClient(server.getAddress().getPort());

            PolicyDecisionResponse response = client.evaluate(OPA_TEST_PATH, createRequest());

            assertEquals(Boolean.FALSE, response.allow());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsDenyWhenOpaIsUnavailable() {
        OpaPolicyDecisionClient client = createClient(1);

        PolicyDecisionResponse response = client.evaluate(OPA_TEST_PATH, createRequest());

        assertEquals(Boolean.FALSE, response.allow());
    }

    @Test
    void returnsDenyWhenOpaReturnsMalformedResponse() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);

        server.createContext(OPA_TEST_PATH, exchange -> {
            byte[] response =
                    """
                {"somethingElse": true}
                """.getBytes(StandardCharsets.UTF_8);

            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.start();

        try {
            OpaPolicyDecisionClient client = createClient(server.getAddress().getPort());

            PolicyDecisionResponse response = client.evaluate(OPA_TEST_PATH, createRequest());

            assertEquals(Boolean.FALSE, response.allow());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsDenyWhenOpaReturnsNullResponse() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);

        server.createContext(OPA_NULL_RESPONSE_PATH, exchange -> {
            byte[] response = "null".getBytes(StandardCharsets.UTF_8);

            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.start();

        try {
            OpaPolicyDecisionClient client = createClient(server.getAddress().getPort());

            PolicyDecisionResponse response = client.evaluate(OPA_NULL_RESPONSE_PATH, createRequest());

            assertEquals(Boolean.FALSE, response.allow());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void sendsStructuredPolicyInputToOpa() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        AtomicReference<String> requestBody = new AtomicReference<>();

        server.createContext(OPA_TEST_PATH, exchange -> {
            requestBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));

            byte[] response =
                    """
                {"result":{"allow":true,"row_filter":null,"policy_version":"test-policy/1.0.0","reasons":["access.granted"]}}
                """
                            .getBytes(StandardCharsets.UTF_8);

            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.start();

        try {
            OpaPolicyDecisionClient client = createClient(server.getAddress().getPort());

            client.evaluate(OPA_TEST_PATH, createRequest());

            assertEquals(
                    """
            {"input":{"subject":{"kind":"user","user_id":"some-client","token":{},"attributes":[],"organisation":null},"action":"some-action","resource":{"kind":"product","attributes":[],"producer":null},"request":{"headers":{},"query":{},"path":null,"body":{}}}}
            """
                            .trim(),
                    requestBody.get());
        } finally {
            server.stop(0);
        }
    }

    private PolicyDecisionRequest createRequest() {
        return new PolicyDecisionRequest(new PolicyInput(
                new PolicySubject("user", "some-client", Map.of(), List.of(), null),
                "some-action",
                new PolicyResource("product", List.of(), null),
                new PolicyRequest(Map.of(), Map.of(), null, Map.of())));
    }

    private OpaPolicyDecisionClient createClient(int port) {
        return new OpaPolicyDecisionClient("http://localhost:" + port, CONNECT_TIMEOUT, READ_TIMEOUT);
    }
}
