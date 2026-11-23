/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.common.utils.ResilienceSupport;
import uk.gov.dbt.ndtp.federator.exceptions.ConfigurationException;

/**
 * Revocation (OCSP) settings, read from the Federator properties file.
 *
 * @param failClosed        a check without a valid status (responder down, circuit open) rejects; false lets it through
 * @param ocspUri           {@code management.node.base.url} + {@code revocation.ocsp.path}
 * @param requestTimeout    timeout of one OCSP attempt; the whole check is bounded by {@link #checkBudget()}
 * @param maxAttempts       {@code revocation.ocsp.resilience.retry.maxAttempts}
 * @param requireNonce      send a nonce and require the response to echo it
 * @param requireSignerEku  require {@code id-kp-OCSPSigning} on a delegated signer certificate
 * @param signerCommonName  transitional: CN accepted for a signer without the EKU when {@code requireSignerEku=false}
 * @param cacheType         {@code memory} or {@code redis}
 * @param cacheTtl          {@code revocation.cache.ttl.seconds}, at most {@link #MAX_CACHE_TTL}
 * @param cacheMaxEntries   size bound of the in-memory cache
 */
public record RevocationProperties(
        boolean failClosed,
        URI ocspUri,
        Duration requestTimeout,
        int maxAttempts,
        boolean requireNonce,
        boolean requireSignerEku,
        String signerCommonName,
        CacheType cacheType,
        Duration cacheTtl,
        int cacheMaxEntries) {

    public static final String ENFORCEMENT_ENABLED = "revocation.enforcement.enabled";
    public static final String FAIL_CLOSED = "revocation.enforcement.failClosed";
    public static final String OCSP_PATH = "revocation.ocsp.path";
    public static final String OCSP_REQUEST_TIMEOUT = "revocation.ocsp.requestTimeout";
    public static final String OCSP_REQUIRE_NONCE = "revocation.ocsp.requireNonce";
    public static final String OCSP_REQUIRE_SIGNER_EKU = "revocation.ocsp.requireSignerEku";
    public static final String OCSP_SIGNER_COMMON_NAME = "revocation.ocsp.signerCommonName";
    public static final String CACHE_TYPE = "revocation.cache.type";
    public static final String CACHE_TTL_SECONDS = "revocation.cache.ttl.seconds";
    public static final String CACHE_MAX_ENTRIES = "revocation.cache.maxEntries";
    public static final String RESILIENCE_PREFIX = "revocation.ocsp.resilience";
    public static final String MANAGEMENT_NODE_BASE_URL = "management.node.base.url";

    public static final String DEFAULT_OCSP_PATH = "/api/v1/certificate/ocsp";
    public static final String DEFAULT_SIGNER_COMMON_NAME = "ocsp-signer.management-node";
    public static final Duration MAX_CACHE_TTL = Duration.ofSeconds(600);

    /** Resilience defaults for OCSP, much shorter than the Management Node configuration calls. */
    public static final ResilienceSupport.Defaults RESILIENCE_DEFAULTS = new ResilienceSupport.Defaults(
            2,
            Duration.ofMillis(100),
            Duration.ofMillis(500),
            OcspResponderException.Retryable.class.getName(),
            50.0f,
            10,
            10,
            1,
            Duration.ofSeconds(30));

    /** Status cache implementation. */
    public enum CacheType {
        MEMORY,
        REDIS
    }

    /**
     * @return the total time a single check may take, including retries: {@code requestTimeout × maxAttempts}
     */
    public Duration checkBudget() {
        return requestTimeout.multipliedBy(maxAttempts);
    }

    /**
     * @return {@code revocation.enforcement.enabled}, default true
     */
    public static boolean isEnforcementEnabled() {
        return PropertyUtil.getPropertyBooleanValue(ENFORCEMENT_ENABLED, "true");
    }

    /**
     * Reads and validates the settings.
     *
     * @return the settings
     * @throws ConfigurationException when a value is missing or out of range; startup must fail
     */
    public static RevocationProperties load() {
        try {
            String baseUrl = PropertyUtil.getPropertyValue(MANAGEMENT_NODE_BASE_URL, "");
            if (baseUrl == null || baseUrl.isBlank()) {
                throw new ConfigurationException(
                        "Revocation checks need " + MANAGEMENT_NODE_BASE_URL + " to reach the OCSP responder");
            }
            String path = PropertyUtil.getPropertyValue(OCSP_PATH, DEFAULT_OCSP_PATH);
            URI uri = URI.create(stripTrailingSlash(baseUrl.trim()) + ensureLeadingSlash(path.trim()));

            int timeoutSeconds = PropertyUtil.getPropertyIntValue(OCSP_REQUEST_TIMEOUT, "2");
            requirePositive(OCSP_REQUEST_TIMEOUT, timeoutSeconds);
            int maxAttempts = PropertyUtil.getPropertyIntValue(
                    RESILIENCE_PREFIX + ".retry.maxAttempts", String.valueOf(RESILIENCE_DEFAULTS.maxAttempts()));
            requirePositive(RESILIENCE_PREFIX + ".retry.maxAttempts", maxAttempts);

            int ttlSeconds = PropertyUtil.getPropertyIntValue(CACHE_TTL_SECONDS, "300");
            requirePositive(CACHE_TTL_SECONDS, ttlSeconds);
            if (ttlSeconds > MAX_CACHE_TTL.toSeconds()) {
                throw new ConfigurationException(CACHE_TTL_SECONDS + " must be at most " + MAX_CACHE_TTL.toSeconds()
                        + " seconds, was " + ttlSeconds);
            }
            int maxEntries = PropertyUtil.getPropertyIntValue(CACHE_MAX_ENTRIES, "10000");
            requirePositive(CACHE_MAX_ENTRIES, maxEntries);

            boolean requireSignerEku = PropertyUtil.getPropertyBooleanValue(OCSP_REQUIRE_SIGNER_EKU, "true");
            if (!requireSignerEku && !"https".equalsIgnoreCase(uri.getScheme())) {
                // Without the EKU, any federation certificate with the signer CN could sign responses. That is only
                // tolerable while the transport authenticates the Management Node itself.
                throw new ConfigurationException(OCSP_REQUIRE_SIGNER_EKU
                        + "=false is only allowed with an https OCSP URL (the Management Node must be authenticated"
                        + " by TLS), was " + uri);
            }

            return new RevocationProperties(
                    PropertyUtil.getPropertyBooleanValue(FAIL_CLOSED, "true"),
                    uri,
                    Duration.ofSeconds(timeoutSeconds),
                    maxAttempts,
                    PropertyUtil.getPropertyBooleanValue(OCSP_REQUIRE_NONCE, "true"),
                    requireSignerEku,
                    PropertyUtil.getPropertyValue(OCSP_SIGNER_COMMON_NAME, DEFAULT_SIGNER_COMMON_NAME)
                            .trim(),
                    parseCacheType(PropertyUtil.getPropertyValue(CACHE_TYPE, "memory")),
                    Duration.ofSeconds(ttlSeconds),
                    maxEntries);
        } catch (IllegalArgumentException e) {
            // NumberFormatException from int properties, or an invalid OCSP URI
            throw new ConfigurationException("Invalid revocation configuration: " + e.getMessage(), e);
        }
    }

    private static CacheType parseCacheType(String value) {
        try {
            return CacheType.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(CACHE_TYPE + " must be 'memory' or 'redis', was '" + value + "'");
        }
    }

    private static void requirePositive(String key, int value) {
        if (value < 1) {
            throw new ConfigurationException(key + " must be at least 1, was " + value);
        }
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String ensureLeadingSlash(String path) {
        return path.startsWith("/") ? path : "/" + path;
    }
}
