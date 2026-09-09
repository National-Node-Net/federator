package uk.gov.dbt.ndtp.federator.common.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
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
            byte[] response = """
                    {"result":{"result":true,"attributes":{}}}
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

            assertEquals(Boolean.TRUE, response.result());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsDenyWhenOpaReturnsFalse() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);

        server.createContext(OPA_TEST_PATH, exchange -> {
            byte[] response = """
                {"result":{"result":false,"attributes":{}}}
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

            assertEquals(Boolean.FALSE, response.result());
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

            assertEquals(Boolean.FALSE, response.result());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsDenyWhenOpaIsUnavailable() {
        OpaPolicyDecisionClient client = createClient(1);

        PolicyDecisionResponse response = client.evaluate(OPA_TEST_PATH, createRequest());

        assertEquals(Boolean.FALSE, response.result());
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

            assertEquals(Boolean.FALSE, response.result());
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

            assertEquals(Boolean.FALSE, response.result());
        } finally {
            server.stop(0);
        }
    }

    private PolicyDecisionRequest createRequest() {
        return new PolicyDecisionRequest(new PolicyInput("consumer-1", null, "test-topic", "consume", Map.of()));
    }

    private OpaPolicyDecisionClient createClient(int port) {
        return new OpaPolicyDecisionClient("http://localhost:" + port, CONNECT_TIMEOUT, READ_TIMEOUT);
    }
}
