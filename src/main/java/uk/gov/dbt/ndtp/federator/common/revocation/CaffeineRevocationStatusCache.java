/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Bounded in-memory status cache ({@code revocation.cache.type=memory}). Each entry expires at the earlier of
 * {@code cachedAt + ttl} and the response's {@code nextUpdate}.
 */
public class CaffeineRevocationStatusCache implements RevocationStatusCache {

    static final String CACHE_NAME = "federator.revocation.status";

    private final Cache<CertificateKey, CertificateStatusEntry> cache;
    private final Duration ttl;
    private final Clock clock;

    public CaffeineRevocationStatusCache(int maxEntries, Duration ttl, Clock clock, MeterRegistry registry) {
        this.ttl = ttl;
        this.clock = clock;
        this.cache = Caffeine.newBuilder()
                .maximumSize(maxEntries)
                .expireAfter(new EntryExpiry())
                .recordStats()
                .build();
        CaffeineCacheMetrics.monitor(registry, cache, CACHE_NAME);
    }

    @Override
    public Optional<CertificateStatusEntry> get(CertificateKey key) {
        CertificateStatusEntry entry = cache.getIfPresent(key);
        if (entry == null) {
            return Optional.empty();
        }
        if (!entry.isFresh(clock.instant(), ttl)) {
            cache.invalidate(key);
            return Optional.empty();
        }
        return Optional.of(entry);
    }

    @Override
    public void put(CertificateKey key, CertificateStatusEntry entry) {
        if (entry.isFresh(clock.instant(), ttl)) {
            cache.put(key, entry);
        }
    }

    @Override
    public String type() {
        return "memory";
    }

    private final class EntryExpiry implements Expiry<CertificateKey, CertificateStatusEntry> {

        private long nanosUntilExpiry(CertificateStatusEntry entry) {
            Duration remaining = Duration.between(Instant.now(clock), entry.expiresAt(ttl));
            return Math.max(remaining.toNanos(), 0);
        }

        @Override
        public long expireAfterCreate(CertificateKey key, CertificateStatusEntry entry, long currentTime) {
            return nanosUntilExpiry(entry);
        }

        @Override
        public long expireAfterUpdate(
                CertificateKey key, CertificateStatusEntry entry, long currentTime, long currentDuration) {
            return nanosUntilExpiry(entry);
        }

        @Override
        public long expireAfterRead(
                CertificateKey key, CertificateStatusEntry entry, long currentTime, long currentDuration) {
            return currentDuration;
        }
    }
}
