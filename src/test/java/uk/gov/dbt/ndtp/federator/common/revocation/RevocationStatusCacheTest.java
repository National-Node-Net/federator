/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import redis.clients.jedis.exceptions.JedisDataException;
import uk.gov.dbt.ndtp.federator.common.revocation.support.RevocationTestSupport.MutableClock;
import uk.gov.dbt.ndtp.federator.common.utils.RedisUtil;

class RevocationStatusCacheTest {

    private static final CertificateKey KEY = new CertificateKey("ab12", "4a1f");
    private static final Instant START = Instant.parse("2026-11-18T10:00:00Z");

    private static CertificateStatusEntry entry(CertificateStatus status, Duration nextUpdateIn) {
        Long nextUpdate = nextUpdateIn == null ? null : START.plus(nextUpdateIn).toEpochMilli();
        return new CertificateStatusEntry(status, START.toEpochMilli(), nextUpdate, START.toEpochMilli());
    }

    @Test
    void entryExpiresAfterTheTtl() {
        MutableClock clock = new MutableClock(START);
        CaffeineRevocationStatusCache cache =
                new CaffeineRevocationStatusCache(10, Duration.ofSeconds(180), clock, new SimpleMeterRegistry());
        cache.put(KEY, entry(CertificateStatus.GOOD, Duration.ofMinutes(5)));

        clock.advance(Duration.ofSeconds(179));
        assertTrue(cache.get(KEY).isPresent());
        clock.advance(Duration.ofSeconds(1));
        assertTrue(cache.get(KEY).isEmpty());
    }

    @Test
    void entryExpiresAtNextUpdateWhenEarlierThanTheTtl() {
        MutableClock clock = new MutableClock(START);
        CaffeineRevocationStatusCache cache =
                new CaffeineRevocationStatusCache(10, Duration.ofSeconds(300), clock, new SimpleMeterRegistry());
        cache.put(KEY, entry(CertificateStatus.REVOKED, Duration.ofSeconds(60)));

        clock.advance(Duration.ofSeconds(59));
        assertEquals(CertificateStatus.REVOKED, cache.get(KEY).orElseThrow().status());
        clock.advance(Duration.ofSeconds(1));
        assertTrue(cache.get(KEY).isEmpty());
    }

    @Test
    void expiredEntryIsNotStored() {
        MutableClock clock = new MutableClock(START.plus(Duration.ofMinutes(10)));
        CaffeineRevocationStatusCache cache =
                new CaffeineRevocationStatusCache(10, Duration.ofSeconds(300), clock, new SimpleMeterRegistry());
        cache.put(KEY, entry(CertificateStatus.GOOD, null));
        assertTrue(cache.get(KEY).isEmpty());
    }

    @Test
    void redisStoresPlainJsonUnderTheCertStatusKeyWithTheRemainingTtl() {
        RedisUtil redis = mock(RedisUtil.class);
        MutableClock clock = new MutableClock(START);
        RedisRevocationStatusCache cache = new RedisRevocationStatusCache(redis, Duration.ofSeconds(300), clock);
        CertificateStatusEntry entry = entry(CertificateStatus.GOOD, Duration.ofSeconds(120));

        cache.put(KEY, entry);

        verify(redis).setValue("cert-status:ab12:4a1f", entry, 120L, false);
    }

    @Test
    void redisReadsWithoutDecryptionAndIgnoresStaleEntries() {
        RedisUtil redis = mock(RedisUtil.class);
        MutableClock clock = new MutableClock(START);
        RedisRevocationStatusCache cache = new RedisRevocationStatusCache(redis, Duration.ofSeconds(300), clock);
        CertificateStatusEntry entry = entry(CertificateStatus.REVOKED, Duration.ofSeconds(60));
        when(redis.getValue("cert-status:ab12:4a1f", CertificateStatusEntry.class, false))
                .thenReturn(entry);

        assertEquals(CertificateStatus.REVOKED, cache.get(KEY).orElseThrow().status());
        clock.advance(Duration.ofSeconds(61));
        assertTrue(cache.get(KEY).isEmpty());
    }

    @Test
    void redisFailureIsACacheMiss() {
        RedisUtil redis = mock(RedisUtil.class);
        when(redis.getValue(anyString(), eq(CertificateStatusEntry.class), anyBoolean()))
                .thenThrow(new JedisDataException("down"));
        when(redis.setValue(anyString(), any(), anyLong(), anyBoolean())).thenThrow(new JedisDataException("down"));
        RedisRevocationStatusCache cache =
                new RedisRevocationStatusCache(redis, Duration.ofSeconds(300), new MutableClock(START));

        assertTrue(cache.get(KEY).isEmpty());
        cache.put(KEY, entry(CertificateStatus.GOOD, null)); // no exception
    }

    @Test
    void redisDoesNotStoreExpiredEntries() {
        RedisUtil redis = mock(RedisUtil.class);
        RedisRevocationStatusCache cache = new RedisRevocationStatusCache(
                redis, Duration.ofSeconds(300), new MutableClock(START.plus(Duration.ofHours(1))));
        cache.put(KEY, entry(CertificateStatus.GOOD, null));
        verify(redis, never()).setValue(anyString(), any(), anyLong(), anyBoolean());
    }
}
