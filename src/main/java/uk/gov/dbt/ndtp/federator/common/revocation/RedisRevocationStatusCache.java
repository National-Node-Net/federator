/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import uk.gov.dbt.ndtp.federator.common.utils.RedisUtil;

/**
 * Status cache shared by all instances through Redis ({@code revocation.cache.type=redis}), using the existing
 * {@code redis.*} connection. Keys are {@code ${redis.prefix}:cert-status:<issuerKeyHash>:<serial>}; values are plain
 * JSON (a status is not a secret, so {@code redis.aes.key} is not applied) with a Redis TTL equal to the remaining
 * lifetime of the entry.
 * <p>
 * A Redis failure is logged and treated as a cache miss, so the check falls back to the OCSP responder.
 */
@Slf4j
public class RedisRevocationStatusCache implements RevocationStatusCache {

    static final String KEY_PREFIX = "cert-status:";

    private final RedisUtil redis;
    private final Duration ttl;
    private final Clock clock;

    public RedisRevocationStatusCache(RedisUtil redis, Duration ttl, Clock clock) {
        this.redis = redis;
        this.ttl = ttl;
        this.clock = clock;
    }

    @Override
    public Optional<CertificateStatusEntry> get(CertificateKey key) {
        try {
            CertificateStatusEntry entry = redis.getValue(redisKey(key), CertificateStatusEntry.class, false);
            if (entry == null || !entry.isFresh(clock.instant(), ttl)) {
                return Optional.empty();
            }
            return Optional.of(entry);
        } catch (RuntimeException e) {
            log.warn("Revocation status cache read failed for {}; asking the OCSP responder: {}", key, e.toString());
            return Optional.empty();
        }
    }

    @Override
    public void put(CertificateKey key, CertificateStatusEntry entry) {
        long remainingMillis = entry.expiresAt(ttl).toEpochMilli() - clock.millis();
        if (remainingMillis <= 0) {
            return;
        }
        long seconds = Math.max(1, remainingMillis / 1000);
        try {
            redis.setValue(redisKey(key), entry, seconds, false);
        } catch (RuntimeException e) {
            log.warn("Revocation status cache write failed for {}: {}", key, e.toString());
        }
    }

    @Override
    public String type() {
        return "redis";
    }

    static String redisKey(CertificateKey key) {
        return KEY_PREFIX + key;
    }
}
