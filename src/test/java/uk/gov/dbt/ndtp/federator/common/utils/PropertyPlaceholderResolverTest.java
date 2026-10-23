/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.common.utils;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PropertyPlaceholderResolverTest {

    private final Map<String, String> systemProperties = new HashMap<>();
    private final Map<String, String> environment = new HashMap<>();
    private PropertyPlaceholderResolver resolver;
    private Properties properties;

    @BeforeEach
    void setUp() {
        resolver = new PropertyPlaceholderResolver(systemProperties::get, environment::get);
        properties = new Properties();
    }

    private String resolve(String value) {
        return resolver.resolve(value, properties);
    }

    @Test
    void valueWithoutPlaceholderIsUnchanged() {
        assertEquals("plain-value", resolve("plain-value"));
        assertEquals("", resolve(""));
        assertNull(resolve(null));
    }

    @Test
    void resolvesFromEnvironment() {
        environment.put("IDP_CLIENT_ID", "env-client");
        assertEquals("env-client", resolve("${IDP_CLIENT_ID}"));
        assertEquals("env-client", resolve("${IDP_CLIENT_ID:default-client}"));
    }

    @Test
    void usesDefaultWhenNotSet() {
        assertEquals("default-client", resolve("${IDP_CLIENT_ID:default-client}"));
    }

    @Test
    void emptyDefault() {
        assertEquals("", resolve("${IDP_CLIENT_SECRET:}"));
    }

    @Test
    void defaultMayContainColons() {
        assertEquals("https://localhost:8090/path", resolve("${MANAGEMENT_NODE_BASE_URL:https://localhost:8090/path}"));
    }

    @Test
    void environmentVariableSetToEmptyCountsAsSet() {
        environment.put("REDIS_PASSWORD", "");
        assertEquals("", resolve("${REDIS_PASSWORD:fallback}"));
    }

    @Test
    void systemPropertyTakesPrecedenceOverEnvironment() {
        environment.put("IDP_CLIENT_ID", "env-client");
        systemProperties.put("IDP_CLIENT_ID", "system-client");
        assertEquals("system-client", resolve("${IDP_CLIENT_ID:default-client}"));
    }

    @Test
    void environmentTakesPrecedenceOverFileProperty() {
        properties.setProperty("IDP_HOST", "file-host");
        environment.put("IDP_HOST", "env-host");
        assertEquals("env-host", resolve("${IDP_HOST}"));
    }

    @Test
    void resolvesReferenceToAnotherProperty() {
        properties.setProperty("idp.base.url", "https://idp.example");
        assertEquals("https://idp.example/token", resolve("${idp.base.url}/token"));
    }

    @Test
    void resolvesMultiplePlaceholdersInOneValue() {
        environment.put("HOST", "idp.example");
        assertEquals("https://idp.example:8443/token", resolve("https://${HOST}:${PORT:8443}/token"));
    }

    @Test
    void resolvesNestedDefault() {
        assertEquals("fallback", resolve("${PRIMARY:${SECONDARY:fallback}}"));
        environment.put("SECONDARY", "secondary");
        assertEquals("secondary", resolve("${PRIMARY:${SECONDARY:fallback}}"));
        environment.put("PRIMARY", "primary");
        assertEquals("primary", resolve("${PRIMARY:${SECONDARY:fallback}}"));
    }

    @Test
    void resolvesPlaceholdersInsideResolvedValues() {
        environment.put("IDP_TOKEN_URL", "${IDP_BASE:https://idp.example}/token");
        assertEquals("https://idp.example/token", resolve("${IDP_TOKEN_URL}"));
    }

    @Test
    void unresolvedPlaceholderWithoutDefaultIsLeftAsIs() {
        assertEquals("${IDP_CLIENT_ID}", resolve("${IDP_CLIENT_ID}"));
        assertEquals("prefix-${MISSING}-suffix", resolve("prefix-${MISSING}-suffix"));
    }

    @Test
    void unterminatedPlaceholderIsLeftAsIs() {
        assertEquals("${IDP_CLIENT_ID", resolve("${IDP_CLIENT_ID"));
    }

    @Test
    void escapedPlaceholderIsKeptLiterally() {
        environment.put("SECRET", "should-not-be-used");
        assertEquals("pa${SECRET}ss", resolve("pa\\${SECRET}ss"));
    }

    @Test
    void escapedPlaceholderFromPropertiesFile() throws IOException {
        // In a .properties file the escape is written as \\${...} because Properties.load consumes one backslash
        Properties loaded = new Properties();
        loaded.load(new StringReader("redis.password=pa\\\\${NOT_A_PLACEHOLDER}ss\n"));
        resolver.resolveAll(loaded);
        assertEquals("pa${NOT_A_PLACEHOLDER}ss", loaded.getProperty("redis.password"));
    }

    @Test
    void referenceToEscapedPropertyIsLiteralRegardlessOfOrder() {
        environment.put("SECRET", "should-not-be-used");
        // Try both insertion orders, since iteration order would otherwise decide whether the escape survives
        for (List<String> order : List.of(List.of("a", "b"), List.of("b", "a"))) {
            Properties props = new Properties();
            for (String key : order) {
                props.setProperty(key, key.equals("a") ? "\\${SECRET}" : "${a}");
            }
            resolver.resolveAll(props);
            assertEquals("${SECRET}", props.getProperty("a"));
            assertEquals("${SECRET}", props.getProperty("b"));
        }
    }

    @Test
    void circularReferencesDoNotLoopForever() {
        properties.setProperty("a", "${b}");
        properties.setProperty("b", "${a}");
        List<String> unresolved = resolver.resolveAll(properties);
        assertEquals(List.of("a", "b"), unresolved.stream().sorted().toList());
    }

    @Test
    void resolveAllUpdatesValuesAndReportsUnresolvedKeys() {
        environment.put("IDP_CLIENT_ID", "env-client");
        properties.setProperty("idp.client.id", "${IDP_CLIENT_ID:default-client}");
        properties.setProperty("idp.token.backoff", "${IDP_TOKEN_BACKOFF:1000}");
        properties.setProperty("idp.token.url", "${IDP_TOKEN_URL}");
        properties.setProperty("redis.host", "localhost");

        List<String> unresolved = resolver.resolveAll(properties);

        assertEquals("env-client", properties.getProperty("idp.client.id"));
        assertEquals("1000", properties.getProperty("idp.token.backoff"));
        assertEquals("${IDP_TOKEN_URL}", properties.getProperty("idp.token.url"));
        assertEquals("localhost", properties.getProperty("redis.host"));
        assertEquals(List.of("idp.token.url"), unresolved);
    }

    @Test
    void fromSystemReadsRealSystemProperties() {
        System.setProperty("federator.placeholder.test", "from-system");
        try {
            assertEquals(
                    "from-system",
                    PropertyPlaceholderResolver.fromSystem()
                            .resolve("${federator.placeholder.test:default}", new Properties()));
        } finally {
            System.clearProperty("federator.placeholder.test");
        }
    }
}
