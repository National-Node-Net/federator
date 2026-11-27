/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redis.testcontainers.RedisContainer;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import redis.clients.jedis.JedisPooled;
import uk.gov.dbt.ndtp.federator.common.revocation.CertificateKey;
import uk.gov.dbt.ndtp.federator.common.revocation.CertificateStatus;
import uk.gov.dbt.ndtp.federator.common.revocation.CertificateStatusEntry;
import uk.gov.dbt.ndtp.federator.common.revocation.RedisRevocationStatusCache;
import uk.gov.dbt.ndtp.federator.common.revocation.support.RevocationTestSupport;

/**
 * Redis status cache against a real Redis: two Federator instances share entries, keys carry the configured prefix
 * and values are plain JSON with a TTL. Skipped when Docker is not available.
 */
@Testcontainers(disabledWithoutDocker = true)
class RedisRevocationStatusCacheContainerTest {

    @Container
    static final RedisContainer REDIS = new RedisContainer(DockerImageName.parse("redis:7.4-alpine"));

    @TempDir
    Path tempDir;

    private JedisPooled jedis;

    @BeforeEach
    void setUp() {
        RevocationTestSupport.initProperties(tempDir, Map.of("redis.prefix", "federator-server"));
        jedis = new JedisPooled(REDIS.getHost(), REDIS.getFirstMappedPort());
        jedis.flushAll();
    }

    @AfterEach
    void tearDown() {
        jedis.close();
        PropertyUtil.clear();
    }

    @Test
    void entryWrittenByOneInstanceIsUsedByAnother() {
        Duration ttl = Duration.ofSeconds(300);
        RedisRevocationStatusCache instanceA =
                new RedisRevocationStatusCache(new RedisUtil(jedis), ttl, Clock.systemUTC());
        RedisRevocationStatusCache instanceB = new RedisRevocationStatusCache(
                new RedisUtil(new JedisPooled(REDIS.getHost(), REDIS.getFirstMappedPort())), ttl, Clock.systemUTC());
        CertificateKey key = new CertificateKey("ab12", "4a1f");
        long now = System.currentTimeMillis();

        instanceA.put(key, new CertificateStatusEntry(CertificateStatus.REVOKED, now, now + 60_000, now));

        assertEquals(CertificateStatus.REVOKED, instanceB.get(key).orElseThrow().status());
        String redisKey = "federator-server:cert-status:ab12:4a1f";
        assertTrue(jedis.get(redisKey).contains("\"status\":\"REVOKED\""), "plain JSON");
        long ttlSeconds = jedis.ttl(redisKey);
        assertTrue(ttlSeconds > 0 && ttlSeconds <= 60, "TTL follows nextUpdate, was " + ttlSeconds);
    }
}
