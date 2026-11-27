/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * A verified OCSP answer for one certificate, as kept in the revocation status cache.
 * <p>
 * Times are epoch milliseconds so the entry serialises to plain JSON (Redis) without extra Jackson modules.
 *
 * @param status     the certificate status
 * @param thisUpdate {@code thisUpdate} of the OCSP single response
 * @param nextUpdate {@code nextUpdate} of the OCSP single response, or {@code null} when the responder did not set it
 * @param cachedAt   when this instance received and verified the response
 */
public record CertificateStatusEntry(CertificateStatus status, long thisUpdate, Long nextUpdate, long cachedAt) {

    public CertificateStatusEntry {
        Objects.requireNonNull(status, "status");
    }

    /**
     * The time after which the entry must not be used: the earlier of {@code cachedAt + ttl} and {@code nextUpdate}.
     *
     * @param ttl the configured cache TTL ({@code revocation.cache.ttl.seconds})
     * @return the expiry time
     */
    public Instant expiresAt(Duration ttl) {
        long byTtl = cachedAt + ttl.toMillis();
        long expiry = nextUpdate == null ? byTtl : Math.min(byTtl, nextUpdate);
        return Instant.ofEpochMilli(expiry);
    }

    /**
     * @return true when the entry is still usable at {@code now}
     */
    public boolean isFresh(Instant now, Duration ttl) {
        return now.isBefore(expiresAt(ttl));
    }
}
