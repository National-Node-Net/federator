/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Entry point for revocation checks: cache first, then the OCSP responder.
 * Verified statuses (good, revoked, unknown) are cached; failures are not.
 * Unexpected exceptions are turned into a {@link RevocationDecision.ResponderFailure}, so callers only handle decisions.
 */
public class RevocationChecker {

    private final OcspClient ocspClient;
    private final RevocationStatusCache cache;
    private final RevocationAudit audit;
    private final Duration ttl;
    private final Clock clock;

    public RevocationChecker(
            OcspClient ocspClient, RevocationStatusCache cache, RevocationAudit audit, Duration ttl, Clock clock) {
        this.ocspClient = Objects.requireNonNull(ocspClient, "ocspClient");
        this.cache = Objects.requireNonNull(cache, "cache");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * The status of a certificate: a fresh cache entry if there is one, otherwise a blocking OCSP query bounded by
     * {@code requestTimeout × maxAttempts}.
     */
    public RevocationDecision check(RevocationTarget target) {
        try {
            Optional<CertificateStatusEntry> cached = cache.get(target.key());
            audit.cacheLookup(cached.isPresent(), cache.type());
            if (cached.isPresent()) {
                return new RevocationDecision.Status(cached.get(), true);
            }
            return query(target);
        } catch (RuntimeException e) {
            return unexpected(e);
        }
    }

    /**
     * Asks the OCSP responder without looking at the cache; used when a cache entry of a peer with open calls
     * has expired. With a shared (Redis) cache another instance may already have refreshed the entry, so a fresh
     * shared entry is used first.
     */
    public RevocationDecision refresh(RevocationTarget target) {
        try {
            if ("redis".equals(cache.type())) {
                Optional<CertificateStatusEntry> shared = cache.get(target.key());
                if (shared.isPresent()) {
                    return new RevocationDecision.Status(shared.get(), true);
                }
            }
            return query(target);
        } catch (RuntimeException e) {
            return unexpected(e);
        }
    }

    private RevocationDecision query(RevocationTarget target) {
        try {
            CertificateStatusEntry entry = ocspClient.query(target.certificateId(), target.issuer());
            cache.put(target.key(), entry);
            return new RevocationDecision.Status(entry, false);
        } catch (OcspResponderException e) {
            return new RevocationDecision.ResponderFailure(e);
        }
    }

    private static RevocationDecision unexpected(RuntimeException e) {
        return new RevocationDecision.ResponderFailure(new OcspResponderException(
                OcspResponderException.Type.INVALID_RESPONSE, "Revocation check failed: " + e, e));
    }

    /**
     * @return when the entry stops being usable
     */
    public Instant expiresAt(CertificateStatusEntry entry) {
        return entry.expiresAt(ttl);
    }

    public Clock clock() {
        return clock;
    }
}
