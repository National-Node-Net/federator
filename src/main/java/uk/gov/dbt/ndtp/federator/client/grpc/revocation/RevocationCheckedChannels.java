/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.client.grpc.revocation;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslProvider;
import java.util.function.UnaryOperator;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationEngine;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.common.utils.SSLUtils;
import uk.gov.dbt.ndtp.federator.exceptions.FederatorSslException;

/**
 * Builds mTLS channels to producers with revocation checks: the producer's certificate is checked in the TLS
 * handshake ({@code OcspTrustManager}) and for every call ({@link ClientRevocationInterceptor}).
 * <p>
 * The SSL context uses the JDK provider, so Netty runs certificate validation (with its blocking OCSP query) as a
 * delegated task on the channel's offload executor rather than on the event loop. The session timeout bounds how long
 * a TLS session can be resumed without a full handshake.
 */
public final class RevocationCheckedChannels {

    public static final String CLIENT_P12_FILE_PATH = "client.p12FilePath";
    public static final String CLIENT_P12_PASSWORD = "client.p12Password";
    public static final String CLIENT_TLS_SESSION_TIMEOUT = "client.tlsSessionTimeout.seconds";
    public static final long DEFAULT_TLS_SESSION_TIMEOUT = 300;

    private RevocationCheckedChannels() {}

    /**
     * @param host      producer host
     * @param port      producer port
     * @param engine    revocation components
     * @param configure the usual channel configuration (keep-alive, auth interceptors)
     * @return the channel
     */
    public static ManagedChannel build(
            String host, int port, RevocationEngine engine, UnaryOperator<ManagedChannelBuilder<?>> configure) {
        KeyManager keyManager = SSLUtils.createKeyManagerFromP12(
                PropertyUtil.getPropertyValue(CLIENT_P12_FILE_PATH),
                PropertyUtil.getPropertyValue(CLIENT_P12_PASSWORD))[0];
        ClientRevocationInterceptor interceptor = new ClientRevocationInterceptor(engine);
        NettyChannelBuilder builder = NettyChannelBuilder.forAddress(host, port)
                .sslContext(sslContext(keyManager, engine.trustManager(), sessionTimeoutSeconds()));
        configure.apply(builder);
        builder.intercept(interceptor);
        ManagedChannel channel = builder.build();
        interceptor.attach(channel);
        return channel;
    }

    static SslContext sslContext(KeyManager keyManager, TrustManager trustManager, long sessionTimeoutSeconds) {
        try {
            return GrpcSslContexts.configure(SslContextBuilder.forClient(), SslProvider.JDK)
                    .keyManager(keyManager)
                    .trustManager(trustManager)
                    .sessionTimeout(sessionTimeoutSeconds)
                    .build();
        } catch (SSLException e) {
            throw new FederatorSslException("Failed to build the gRPC client SSL context", e);
        }
    }

    /** {@code client.tlsSessionTimeout.seconds}; empty means the default of 300 seconds. */
    static long sessionTimeoutSeconds() {
        String value = PropertyUtil.getPropertyValue(CLIENT_TLS_SESSION_TIMEOUT, null);
        return value == null || value.isBlank() ? DEFAULT_TLS_SESSION_TIMEOUT : Long.parseLong(value.trim());
    }
}
