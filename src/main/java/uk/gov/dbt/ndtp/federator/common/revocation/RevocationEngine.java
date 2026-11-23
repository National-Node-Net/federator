/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import io.github.resilience4j.micrometer.tagged.TaggedCircuitBreakerMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import java.net.http.HttpClient;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.X509ExtendedTrustManager;
import lombok.extern.slf4j.Slf4j;
import uk.gov.dbt.ndtp.federator.common.service.idp.IdpTokenService;
import uk.gov.dbt.ndtp.federator.common.utils.RedisUtil;
import uk.gov.dbt.ndtp.federator.common.utils.ResilienceSupport;

/**
 * The revocation components shared by the producer and the consumer, built from the {@code revocation.*} settings:
 * OCSP client, status cache, checker, handshake trust manager and the registry of open calls.
 *
 * @param properties     validated settings
 * @param audit          logs and metrics, tagged with the component ({@code producer} or {@code consumer})
 * @param checker        cache-then-OCSP status checks
 * @param trustManager   trust manager for the TLS context (handshake check)
 * @param registry       open calls and their re-checks
 * @param trustedIssuers CA certificates of the truststore, to find the issuer of a peer that sends only its leaf
 * @param tokenProvider  bearer token source for the OCSP endpoint
 */
@Slf4j
public record RevocationEngine(
        RevocationProperties properties,
        RevocationAudit audit,
        RevocationChecker checker,
        OcspTrustManager trustManager,
        ActiveCallRegistry registry,
        List<X509Certificate> trustedIssuers,
        OcspTokenProvider tokenProvider)
        implements AutoCloseable {

    /**
     * Reads and validates the settings and builds the components.
     *
     * @param component    {@code producer} or {@code consumer}, used in logs and metric tags
     * @param pkix         PKIX trust manager of the gRPC truststore
     * @param httpClient   Management Node HTTP client (mTLS identity {@code idp.keystore.*})
     * @param tokenService IdP token service for the OCSP endpoint's bearer token
     * @param meters       meter registry
     * @throws uk.gov.dbt.ndtp.federator.exceptions.ConfigurationException when a setting is invalid
     */
    public static RevocationEngine build(
            String component,
            X509ExtendedTrustManager pkix,
            HttpClient httpClient,
            IdpTokenService tokenService,
            MeterRegistry meters) {
        Objects.requireNonNull(pkix, "pkix");
        RevocationProperties properties = RevocationProperties.load();
        Clock clock = Clock.systemUTC();
        RevocationAudit audit = new RevocationAudit(component, meters);

        ResilienceSupport.Policy policy = new ResilienceSupport.Policy(
                RevocationProperties.RESILIENCE_PREFIX, RevocationProperties.RESILIENCE_DEFAULTS);
        TaggedCircuitBreakerMetrics.ofCircuitBreakerRegistry(policy.circuitBreakerRegistry())
                .bindTo(meters);
        OcspTokenProvider tokenProvider = new OcspTokenProvider(tokenService, clock);
        OcspResponseVerifier verifier = new OcspResponseVerifier(
                properties.requireNonce(), properties.requireSignerEku(), properties.signerCommonName(), clock);
        OcspClient ocspClient = new OcspClient(httpClient, tokenProvider, verifier, policy, audit, properties);
        RevocationStatusCache cache =
                switch (properties.cacheType()) {
                    case MEMORY ->
                        new CaffeineRevocationStatusCache(
                                properties.cacheMaxEntries(), properties.cacheTtl(), clock, meters);
                    case REDIS -> new RedisRevocationStatusCache(RedisUtil.getInstance(), properties.cacheTtl(), clock);
                };
        RevocationChecker checker = new RevocationChecker(ocspClient, cache, audit, properties.cacheTtl(), clock);
        ActiveCallRegistry registry = new ActiveCallRegistry(checker, audit, properties.failClosed());
        OcspTrustManager trustManager = new OcspTrustManager(pkix, checker, audit, properties.failClosed());

        logSettings(component, properties);
        return new RevocationEngine(
                properties, audit, checker, trustManager, registry, List.of(pkix.getAcceptedIssuers()), tokenProvider);
    }

    private static void logSettings(String component, RevocationProperties properties) {
        log.info(
                "Certificate revocation checks enabled ({}): ocsp={} cache={} ttl={}s failClosed={} requireNonce={}"
                        + " requireSignerEku={} budget={}ms",
                component,
                properties.ocspUri(),
                properties.cacheType(),
                properties.cacheTtl().toSeconds(),
                properties.failClosed(),
                properties.requireNonce(),
                properties.requireSignerEku(),
                properties.checkBudget().toMillis());
        if (!properties.requireSignerEku()) {
            log.warn(
                    "{}=false: OCSP signer certificates without id-kp-OCSPSigning are accepted when their CN is '{}'."
                            + " This is transitional.",
                    RevocationProperties.OCSP_REQUIRE_SIGNER_EKU,
                    properties.signerCommonName());
        }
        if (!properties.failClosed()) {
            log.warn(
                    "{}=false: peers are accepted when their certificate status is unavailable",
                    RevocationProperties.FAIL_CLOSED);
        }
    }

    @Override
    public void close() {
        registry.close();
        tokenProvider.close();
    }
}
