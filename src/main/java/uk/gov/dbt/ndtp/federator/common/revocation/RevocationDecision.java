/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.util.Objects;

/**
 * Outcome of a revocation check: either a verified status (from the cache or a fresh OCSP response) or a responder
 * failure when no valid status is available.
 */
public sealed interface RevocationDecision {

    /** Tag used in logs and metrics when no status is available. */
    String UNAVAILABLE = "unavailable";

    /**
     * @return true for a verified {@code GOOD} status
     */
    default boolean isGood() {
        return this instanceof Status status && status.status() == CertificateStatus.GOOD;
    }

    /**
     * @return {@code good}, {@code revoked}, {@code unknown} or {@code unavailable}
     */
    default String statusTag() {
        return switch (this) {
            case Status status -> status.status().name().toLowerCase(java.util.Locale.ROOT);
            case ResponderFailure ignored -> UNAVAILABLE;
        };
    }

    /**
     * @return the responder failure type, or null for a verified status
     */
    default String detail() {
        return switch (this) {
            case Status status -> status.fromCache() ? "cache" : "ocsp";
            case ResponderFailure failure ->
                failure.cause().getType().tag() + ": " + failure.cause().getMessage();
        };
    }

    /**
     * A verified status.
     *
     * @param entry     the status entry
     * @param fromCache true when the entry came from the cache rather than a fresh OCSP response
     */
    record Status(CertificateStatusEntry entry, boolean fromCache) implements RevocationDecision {
        public Status {
            Objects.requireNonNull(entry, "entry");
        }

        public CertificateStatus status() {
            return entry.status();
        }
    }

    /**
     * No valid status: the responder failed and nothing usable is cached.
     *
     * @param cause the responder failure
     */
    record ResponderFailure(OcspResponderException cause) implements RevocationDecision {
        public ResponderFailure {
            Objects.requireNonNull(cause, "cause");
        }
    }
}
