/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.client.grpc.revocation;

import io.micrometer.core.instrument.MeterRegistry;
import java.net.http.HttpClient;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import javax.net.ssl.X509ExtendedTrustManager;
import lombok.extern.slf4j.Slf4j;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationEngine;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationProperties;
import uk.gov.dbt.ndtp.federator.common.service.idp.IdpTokenService;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;

/**
 * Revocation checks of producer certificates on the consumer, set up once at startup and used by every channel.
 * <ul>
 *     <li>{@code client.tlsEnabled=false}: nothing is built; WARN that checks are inactive because mTLS is off.</li>
 *     <li>{@code revocation.enforcement.enabled=false}: nothing is built; WARN.</li>
 *     <li>Otherwise the settings are validated (an invalid value fails startup) and the components are built. Checks
 *     apply to every producer connection that uses TLS ({@code tls=true} in the Management Node configuration).</li>
 * </ul>
 */
@Slf4j
public final class ClientRevocation {

    public static final String CLIENT_TLS_ENABLED = "client.tlsEnabled";
    static final String COMPONENT = "consumer";

    private static final AtomicReference<RevocationEngine> ENGINE = new AtomicReference<>();

    private ClientRevocation() {}

    /**
     * Builds the components, or nothing when checks are off, and makes them available to new channels.
     *
     * @param pkix         trust manager built from {@code client.truststoreFilePath}
     * @param httpClient   creates the Management Node HTTP client (mTLS identity {@code idp.keystore.*}); only called
     *                     when checks are applied
     * @param tokenService IdP token service for the OCSP endpoint's bearer token
     * @param meters       meter registry
     * @return the components, or empty when checks are not applied
     */
    public static Optional<RevocationEngine> install(
            Supplier<X509ExtendedTrustManager> pkix,
            Supplier<HttpClient> httpClient,
            Supplier<IdpTokenService> tokenService,
            MeterRegistry meters) {
        close();
        if (!PropertyUtil.getPropertyBooleanValue(CLIENT_TLS_ENABLED, "true")) {
            log.warn(
                    "Certificate revocation checks are inactive because mTLS is disabled ({}=false)",
                    CLIENT_TLS_ENABLED);
            return Optional.empty();
        }
        if (!RevocationProperties.isEnforcementEnabled()) {
            log.warn(
                    "Certificate revocation checks are disabled ({}=false); revoked producer certificates are accepted",
                    RevocationProperties.ENFORCEMENT_ENABLED);
            return Optional.empty();
        }
        RevocationEngine engine =
                RevocationEngine.build(COMPONENT, pkix.get(), httpClient.get(), tokenService.get(), meters);
        ENGINE.set(engine);
        return Optional.of(engine);
    }

    /**
     * @return the installed components, or empty when checks are not applied
     */
    public static Optional<RevocationEngine> engine() {
        return Optional.ofNullable(ENGINE.get());
    }

    /** Stops the re-check scheduler and removes the components. */
    public static void close() {
        RevocationEngine engine = ENGINE.getAndSet(null);
        if (engine != null) {
            engine.close();
        }
    }
}
