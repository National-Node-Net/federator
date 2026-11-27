/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import uk.gov.dbt.ndtp.federator.common.revocation.support.RevocationTestSupport;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.exceptions.ConfigurationException;

class RevocationPropertiesTest {

    @TempDir
    Path tempDir;

    @AfterEach
    void tearDown() {
        PropertyUtil.clear();
    }

    private RevocationProperties load(Map<String, String> extra) {
        Map<String, String> values = new HashMap<>(Map.of("management.node.base.url", "https://mn:8090/"));
        values.putAll(extra);
        RevocationTestSupport.initProperties(tempDir, values);
        return RevocationProperties.load();
    }

    @Test
    void defaultsFollowTheTicketAndTheManagementNodeContract() {
        RevocationProperties properties = load(Map.of());
        assertEquals(URI.create("https://mn:8090/api/v1/certificate/ocsp"), properties.ocspUri());
        assertEquals(Duration.ofSeconds(300), properties.cacheTtl());
        assertEquals(Duration.ofSeconds(2), properties.requestTimeout());
        assertEquals(2, properties.maxAttempts());
        assertEquals(Duration.ofSeconds(4), properties.checkBudget());
        assertEquals(RevocationProperties.CacheType.MEMORY, properties.cacheType());
        assertEquals(10000, properties.cacheMaxEntries());
        assertTrue(properties.failClosed());
        assertTrue(properties.requireNonce());
        assertTrue(properties.requireSignerEku());
        assertEquals("ocsp-signer.management-node", properties.signerCommonName());
        assertTrue(RevocationProperties.isEnforcementEnabled());
    }

    @Test
    void ttlIsConfigurable() {
        assertEquals(
                Duration.ofSeconds(180),
                load(Map.of("revocation.cache.ttl.seconds", "180")).cacheTtl());
    }

    @Test
    void ttlAboveSixHundredSecondsFailsStartup() {
        Map<String, String> properties = Map.of("revocation.cache.ttl.seconds", "601");
        ConfigurationException e = assertThrows(ConfigurationException.class, () -> load(properties));
        assertTrue(e.getMessage().contains("revocation.cache.ttl.seconds"));
    }

    @Test
    void ttlOfSixHundredSecondsIsAllowed() {
        assertEquals(
                Duration.ofSeconds(600),
                load(Map.of("revocation.cache.ttl.seconds", "600")).cacheTtl());
    }

    @ParameterizedTest
    @CsvSource({
        "revocation.cache.ttl.seconds, 0",
        "revocation.cache.ttl.seconds, abc",
        "revocation.cache.type, disk",
        "revocation.ocsp.requestTimeout, 0",
        "revocation.ocsp.resilience.retry.maxAttempts, 0"
    })
    void invalidValuesFailStartup(String key, String value) {
        Map<String, String> properties = Map.of(key, value);
        assertThrows(ConfigurationException.class, () -> load(properties));
    }

    @Test
    void missingManagementNodeUrlFailsStartup() {
        RevocationTestSupport.initProperties(tempDir, Map.of());
        assertThrows(ConfigurationException.class, RevocationProperties::load);
    }

    @Test
    void pathAndCacheTypeAreConfigurable() {
        RevocationProperties properties =
                load(Map.of("revocation.ocsp.path", "ocsp", "revocation.cache.type", "Redis"));
        assertEquals(URI.create("https://mn:8090/ocsp"), properties.ocspUri());
        assertEquals(RevocationProperties.CacheType.REDIS, properties.cacheType());
    }

    @Test
    void transitionalSignerModeRequiresHttps() {
        RevocationTestSupport.initProperties(
                tempDir,
                Map.of("management.node.base.url", "http://mn:8090", "revocation.ocsp.requireSignerEku", "false"));
        ConfigurationException e = assertThrows(ConfigurationException.class, RevocationProperties::load);
        assertTrue(e.getMessage().contains("https"));

        assertFalse(load(Map.of("revocation.ocsp.requireSignerEku", "false")).requireSignerEku());
    }

    @Test
    void enforcementFlag() {
        load(Map.of("revocation.enforcement.enabled", "false"));
        assertFalse(RevocationProperties.isEnforcementEnabled());
    }
}
