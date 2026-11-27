/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.server.grpc.revocation;

import io.micrometer.core.instrument.MeterRegistry;
import java.net.http.HttpClient;
import java.util.Optional;
import java.util.function.Supplier;
import javax.net.ssl.X509ExtendedTrustManager;
import lombok.extern.slf4j.Slf4j;
import uk.gov.dbt.ndtp.federator.common.revocation.ActiveCallRegistry;
import uk.gov.dbt.ndtp.federator.common.revocation.OcspTrustManager;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationEngine;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationProperties;
import uk.gov.dbt.ndtp.federator.common.service.idp.IdpTokenService;

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
     * @param engine       the shared components (checker, cache, open calls and their re-checks)
     */
    public record Components(
            OcspTrustManager trustManager, ServerRevocationInterceptor interceptor, RevocationEngine engine)
            implements AutoCloseable {

        public ActiveCallRegistry registry() {
            return engine.registry();
        }

        @Override
        public void close() {
            engine.close();
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
        RevocationEngine engine = RevocationEngine.build(COMPONENT, pkix, httpClient.get(), tokenService, meters);
        ServerRevocationInterceptor interceptor = new ServerRevocationInterceptor(
                engine.checker(),
                engine.registry(),
                engine.audit(),
                engine.trustedIssuers(),
                engine.properties().failClosed());
        return Optional.of(new Components(engine.trustManager(), interceptor, engine));
    }
}
