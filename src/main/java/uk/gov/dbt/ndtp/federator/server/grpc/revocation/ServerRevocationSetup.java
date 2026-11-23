/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.server.grpc.revocation;

import io.github.resilience4j.micrometer.tagged.TaggedCircuitBreakerMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import java.net.http.HttpClient;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import javax.net.ssl.X509ExtendedTrustManager;
import lombok.extern.slf4j.Slf4j;
import uk.gov.dbt.ndtp.federator.common.revocation.CaffeineRevocationStatusCache;
import uk.gov.dbt.ndtp.federator.common.revocation.OcspClient;
import uk.gov.dbt.ndtp.federator.common.revocation.OcspResponseVerifier;
import uk.gov.dbt.ndtp.federator.common.revocation.OcspTokenProvider;
import uk.gov.dbt.ndtp.federator.common.revocation.OcspTrustManager;
import uk.gov.dbt.ndtp.federator.common.revocation.RedisRevocationStatusCache;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationChecker;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationProperties;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationStatusCache;
import uk.gov.dbt.ndtp.federator.common.service.idp.IdpTokenService;
import uk.gov.dbt.ndtp.federator.common.utils.RedisUtil;
import uk.gov.dbt.ndtp.federator.common.utils.ResilienceSupport;

/**
 * Decides at startup whether the producer checks consumer certificates for revocation, and builds the components.
 * <ul>
 *     <li>{@code server.mtlsEnabled=false}: nothing is built; WARN that checks are inactive because mTLS is off.</li>
 *     <li>{@code revocation.enforcement.enabled=false}: nothing is built; WARN.</li>
 *     <li>Otherwise the settings are validated (an invalid value fails startup) and the components are built.</li>
 * </ul>
 */
@Slf4j
public final class ServerRevocationSetup {

    static final String COMPONENT = "producer";

    private ServerRevocationSetup() {}

    /**
     * The revocation components of the producer.
     *
     * @param trustManager trust manager for the server SSL context (handshake check)
     * @param interceptor  server interceptor (per-call check); register it last
     * @param registry     open calls and their re-checks
     */
    public record Components(
            OcspTrustManager trustManager,
            ServerRevocationInterceptor interceptor,
            ActiveCallRegistry registry,
            OcspTokenProvider tokenProvider)
            implements AutoCloseable {

        @Override
        public void close() {
            registry.close();
            tokenProvider.close();
        }
    }

    /**
     * @param mtlsEnabled  {@code server.mtlsEnabled}
     * @param pkix         trust manager built from {@code server.truststoreFilePath}
     * @param httpClient   creates the Management Node HTTP client (mTLS identity {@code idp.keystore.*}); only
     *                     called when checks are applied
     * @param tokenService IdP token service for the OCSP endpoint's bearer token
     * @param meters       meter registry
     * @return the components, or empty when checks are not applied
     */
    public static Optional<Components> create(
            boolean mtlsEnabled,
            X509ExtendedTrustManager pkix,
            Supplier<HttpClient> httpClient,
            IdpTokenService tokenService,
            MeterRegistry meters) {
        if (!mtlsEnabled) {
            log.warn("Certificate revocation checks are inactive because mTLS is disabled (server.mtlsEnabled=false)");
            return Optional.empty();
        }
        if (!RevocationProperties.isEnforcementEnabled()) {
            log.warn(
                    "Certificate revocation checks are disabled ({}=false); revoked consumer certificates are accepted",
                    RevocationProperties.ENFORCEMENT_ENABLED);
            return Optional.empty();
        }
        RevocationProperties properties = RevocationProperties.load();
        Clock clock = Clock.systemUTC();
        RevocationAudit audit = new RevocationAudit(COMPONENT, meters);

        ResilienceSupport.Policy policy = new ResilienceSupport.Policy(
                RevocationProperties.RESILIENCE_PREFIX, RevocationProperties.RESILIENCE_DEFAULTS);
        TaggedCircuitBreakerMetrics.ofCircuitBreakerRegistry(policy.circuitBreakerRegistry())
                .bindTo(meters);
        OcspTokenProvider tokenProvider = new OcspTokenProvider(tokenService, clock);
        OcspResponseVerifier verifier = new OcspResponseVerifier(
                properties.requireNonce(), properties.requireSignerEku(), properties.signerCommonName(), clock);
        OcspClient ocspClient = new OcspClient(httpClient.get(), tokenProvider, verifier, policy, audit, properties);
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
        ServerRevocationInterceptor interceptor = new ServerRevocationInterceptor(
                checker, registry, audit, List.of(pkix.getAcceptedIssuers()), properties.failClosed());

        log.info(
                "Certificate revocation checks enabled: ocsp={} cache={} ttl={}s failClosed={} requireNonce={}"
                        + " requireSignerEku={} budget={}ms",
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
                    "{}=false: consumers are accepted when their certificate status is unavailable",
                    RevocationProperties.FAIL_CLOSED);
        }
        return Optional.of(new Components(trustManager, interceptor, registry, tokenProvider));
    }
}
