/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.util.Optional;

/**
 * Cache of verified certificate statuses, keyed by {@code issuerKeyHash:serial}.
 * Only verified statuses are stored; responder failures are never cached.
 * An entry is not returned after {@link CertificateStatusEntry#expiresAt}.
 */
public interface RevocationStatusCache {

    /**
     * @return the entry if one is cached and not expired
     */
    Optional<CertificateStatusEntry> get(CertificateKey key);

    /**
     * Stores an entry until its expiry. An already expired entry is not stored.
     */
    void put(CertificateKey key, CertificateStatusEntry entry);

    /**
     * @return {@code memory} or {@code redis}, used as a metric tag
     */
    String type();
}
