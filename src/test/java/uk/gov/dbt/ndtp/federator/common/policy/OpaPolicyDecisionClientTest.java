package uk.gov.dbt.ndtp.federator.common.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class OpaPolicyDecisionClientTest {

    @Test
    void returnsAllowWhenOpaReturnsTrue() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);

        server.createContext("/v1/data", exchange -> {
            byte[] response =
                    """
                    {"result": true}
                    """.getBytes(StandardCharsets.UTF_8);

            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.start();

        try {
            int port = server.getAddress().getPort();

            OpaPolicyDecisionClient client = new OpaPolicyDecisionClient("http://localhost:" + port, "/v1/data", 5, 5);

            PolicyDecisionRequest request =
                    new PolicyDecisionRequest(new PolicyInput("consumer-1", null, "test-topic", "consume"));

            PolicyDecisionResponse response = client.evaluate(request);

            assertEquals(Boolean.TRUE, response.result());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsDenyWhenOpaReturnsFalse() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);

        server.createContext("/v1/data", exchange -> {
            byte[] response =
                    """
                {"result": false}
                """.getBytes(StandardCharsets.UTF_8);

            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.start();

        try {
            int port = server.getAddress().getPort();

            OpaPolicyDecisionClient client = new OpaPolicyDecisionClient("http://localhost:" + port, "/v1/data", 5, 5);

            PolicyDecisionRequest request =
                    new PolicyDecisionRequest(new PolicyInput("consumer-1", null, "test-topic", "consume"));

            PolicyDecisionResponse response = client.evaluate(request);

            assertNotEquals(Boolean.TRUE, response.result());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsDenyWhenOpaReturnsServerError() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);

        server.createContext("/v1/data", exchange -> {
            exchange.sendResponseHeaders(500, -1);
            exchange.close();
        });

        server.start();

        try {
            int port = server.getAddress().getPort();

            OpaPolicyDecisionClient client = new OpaPolicyDecisionClient("http://localhost:" + port, "/v1/data", 5, 5);

            PolicyDecisionRequest request =
                    new PolicyDecisionRequest(new PolicyInput("consumer-1", null, "test-topic", "consume"));

            PolicyDecisionResponse response = client.evaluate(request);

            assertNotEquals(Boolean.TRUE, response.result());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsDenyWhenOpaIsUnavailable() {
        OpaPolicyDecisionClient client = new OpaPolicyDecisionClient("http://localhost:1", "/v1/data", 5, 5);

        PolicyDecisionRequest request =
                new PolicyDecisionRequest(new PolicyInput("consumer-1", null, "test-topic", "consume"));

        PolicyDecisionResponse response = client.evaluate(request);

        assertNotEquals(Boolean.TRUE, response.result());
    }

    @Test
    void returnsDenyWhenOpaReturnsMalformedResponse() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);

        server.createContext("/v1/data", exchange -> {
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
            int port = server.getAddress().getPort();

            OpaPolicyDecisionClient client = new OpaPolicyDecisionClient("http://localhost:" + port, "/v1/data", 5, 5);

            PolicyDecisionRequest request =
                    new PolicyDecisionRequest(new PolicyInput("consumer-1", null, "test-topic", "consume"));

            PolicyDecisionResponse response = client.evaluate(request);

            assertNotEquals(Boolean.TRUE, response.result());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsDenyWhenOpaReturnsNullResponse() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);

        server.createContext("/v1/data/test/allow", exchange -> {
            byte[] response = "null".getBytes();

            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.start();

        try {
            OpaPolicyDecisionClient client = new OpaPolicyDecisionClient(
                    "http://localhost:" + server.getAddress().getPort(), "/v1/data/test/allow", 5, 5);

            PolicyDecisionResponse response = client.evaluate(
                    new PolicyDecisionRequest(new PolicyInput("client-1", null, "test-topic", "consume")));

            assertNotEquals(Boolean.TRUE, response.result());
        } finally {
            server.stop(0);
        }
    }
}
