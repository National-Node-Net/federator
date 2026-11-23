// SPDX-License-Identifier: Apache-2.0
// Originally developed by Telicent Ltd.; subsequently adapted, enhanced, and maintained by the National Digital Twin
// Programme.

/*
 *  Copyright (c) Telicent Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Modifications made by the National Digital Twin Programme (NDTP)
 *  © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme
 *  and is legally attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.server.grpc;

import static uk.gov.dbt.ndtp.federator.common.utils.GRPCUtils.*;

import io.grpc.Server;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.ClientAuth;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslProvider;
import io.micrometer.core.instrument.MeterRegistry;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.dbt.ndtp.federator.common.annotations.ExcludeFromJacocoGeneratedReport;
import uk.gov.dbt.ndtp.federator.common.metrics.MetricsServer;
import uk.gov.dbt.ndtp.federator.common.revocation.OcspTrustManager;
import uk.gov.dbt.ndtp.federator.common.service.idp.IdpTokenService;
import uk.gov.dbt.ndtp.federator.common.utils.GRPCUtils;
import uk.gov.dbt.ndtp.federator.common.utils.HttpClientFactoryUtils;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.common.utils.SSLUtils;
import uk.gov.dbt.ndtp.federator.common.utils.ThreadUtil;
import uk.gov.dbt.ndtp.federator.exceptions.FederatorSslException;
import uk.gov.dbt.ndtp.federator.server.grpc.interceptor.AuthServerInterceptor;
import uk.gov.dbt.ndtp.federator.server.grpc.interceptor.ConsumerVerificationServerInterceptor;
import uk.gov.dbt.ndtp.federator.server.grpc.interceptor.CustomServerInterceptor;
import uk.gov.dbt.ndtp.federator.server.grpc.revocation.ServerRevocationSetup;

/**
 * GRPCServer is a server for the FederatorService GRPC service.
 * It is used to start the GRPC server.
 * It is also used to generate the GRPC server with filters and shared headers.
 * It is also used to close the GRPC server.
 * <p>
 * With {@code server.mtlsEnabled=true} and {@code revocation.enforcement.enabled=true}, consumer certificates are
 * checked for revocation in the TLS handshake, at the start of every call and while calls are open
 * (see {@link ServerRevocationSetup}).
 */
public class GRPCServer implements AutoCloseable {
    public static final String GRPC_SERVER = "GRPCServer";
    public static final Logger LOGGER = LoggerFactory.getLogger(GRPC_SERVER);

    public static final String SERVER_PORT = "server.port";
    public static final String DEFAULT_PORT = "8080";
    public static final String SERVER_KEEP_ALIVE_TIME = "server.keepAliveTime";
    public static final String SERVER_KEEP_ALIVE_TIMEOUT = "server.keepAliveTimeout";
    public static final String SERVER_MTLS_ENABLED = "server.mtlsEnabled";
    public static final String SERVER_MAX_CONNECTION_AGE = "server.maxConnectionAge.seconds";
    public static final String SERVER_MAX_CONNECTION_AGE_GRACE = "server.maxConnectionAgeGrace.seconds";
    public static final String SERVER_MAX_CONNECTION_IDLE = "server.maxConnectionIdle.seconds";
    public static final String SERVER_TLS_SESSION_TIMEOUT = "server.tlsSessionTimeout.seconds";
    public static final String DEFAULT_MAX_CONNECTION_AGE = "1800";
    public static final String DEFAULT_TLS_SESSION_TIMEOUT = "300";
    public static final String FIVE = "5";
    public static final String ONE = "1";
    public static final String FALSE = "false";

    private static final String SERVER_P12_FILE_PATH = "server.p12FilePath";
    private static final String SERVER_P12_PASSWORD = "server.p12Password";
    private static final String SERVER_TRUSTSTORE_FILE_PATH = "server.truststoreFilePath";
    private static final String SERVER_TRUSTSTORE_PASSWORD = "server.truststorePassword";

    private final Server server;
    private final GRPCFederatorService grpcFederatorService;
    private final Optional<ServerRevocationSetup.Components> revocation;

    public GRPCServer(Set<String> sharedHeaders) {
        this(new GRPCFederatorService(sharedHeaders), GRPCUtils.createIdpTokenService(), MetricsServer.registry());
    }

    GRPCServer(GRPCFederatorService grpcFederatorService, IdpTokenService tokenService, MeterRegistry meters) {
        this.grpcFederatorService = grpcFederatorService;
        Properties idpProperties = PropertyUtil.getIdpProperties();
        NettyServerBuilder builder =
                NettyServerBuilder.forPort(PropertyUtil.getPropertyIntValue(SERVER_PORT, DEFAULT_PORT));

        if (PropertyUtil.getPropertyBooleanValue(SERVER_MTLS_ENABLED, FALSE)) {
            KeyManager[] keyManagers = loadKeyManagers();
            X509ExtendedTrustManager pkix = OcspTrustManager.pkixDelegate(loadTrustManagers());
            revocation = ServerRevocationSetup.create(
                    true,
                    pkix,
                    () -> HttpClientFactoryUtils.createHttpClientWithMtls(idpProperties),
                    tokenService,
                    meters);
            TrustManager trustManager = revocation
                    .<TrustManager>map(ServerRevocationSetup.Components::trustManager)
                    .orElse(pkix);
            builder.sslContext(buildSslContext(keyManagers[0], trustManager));
        } else {
            LOGGER.warn("Server TLS is not enabled, using insecure server.");
            revocation = ServerRevocationSetup.create(false, null, null, tokenService, meters);
        }
        configureConnectionLifecycle(builder, revocation.isPresent());
        server = configureServerBuilder(builder, tokenService, idpProperties).build();
    }

    private NettyServerBuilder configureServerBuilder(
            NettyServerBuilder builder, IdpTokenService tokenService, Properties idpProperties) {
        // ServerInterceptors.intercept runs the LAST interceptor FIRST: the revocation check goes last so a revoked
        // certificate is rejected before JWT validation, consumer authorisation and OPA.
        List<ServerInterceptor> interceptors = new ArrayList<>(List.of(
                new ConsumerVerificationServerInterceptor(tokenService, idpProperties),
                new AuthServerInterceptor(tokenService),
                new CustomServerInterceptor()));
        revocation.ifPresent(components -> interceptors.add(components.interceptor()));

        builder.executor(ThreadUtil.threadExecutor(GRPC_SERVER))
                .keepAliveTime(PropertyUtil.getPropertyIntValue(SERVER_KEEP_ALIVE_TIME, FIVE), TimeUnit.SECONDS)
                .keepAliveTimeout(PropertyUtil.getPropertyIntValue(SERVER_KEEP_ALIVE_TIMEOUT, ONE), TimeUnit.SECONDS)
                .addService(ServerInterceptors.intercept(grpcFederatorService, interceptors));
        return builder;
    }

    /**
     * {@code maxConnectionAge} sends GOAWAY to old connections, so new calls go over a new connection with a full
     * handshake (and revocation check). It applies with revocation checks active (default 1800 s) or when set
     * explicitly. An empty value (a {@code ${VAR:}} placeholder without a default) counts as not set.
     * <p>
     * {@code maxConnectionAgeGrace} is applied only when set: it forcibly ends calls still running that long after
     * GOAWAY, which would cut long-lived streams of good consumers. A revoked consumer's open calls are closed by the
     * re-check instead.
     */
    static void configureConnectionLifecycle(NettyServerBuilder builder, boolean revocationActive) {
        String maxAge = PropertyUtil.getPropertyValue(SERVER_MAX_CONNECTION_AGE, null);
        if ((maxAge == null || maxAge.isBlank()) && revocationActive) {
            maxAge = DEFAULT_MAX_CONNECTION_AGE;
        }
        if (maxAge != null && !maxAge.isBlank()) {
            long age = Long.parseLong(maxAge.trim());
            builder.maxConnectionAge(age, TimeUnit.SECONDS);
            String grace = PropertyUtil.getPropertyValue(SERVER_MAX_CONNECTION_AGE_GRACE, null);
            String graceLog = "unlimited";
            if (grace != null && !grace.isBlank()) {
                long graceSeconds = Long.parseLong(grace.trim());
                builder.maxConnectionAgeGrace(graceSeconds, TimeUnit.SECONDS);
                graceLog = graceSeconds + "s";
            }
            LOGGER.info("gRPC maxConnectionAge={}s maxConnectionAgeGrace={}", age, graceLog);
        }
        String maxIdle = PropertyUtil.getPropertyValue(SERVER_MAX_CONNECTION_IDLE, null);
        if (maxIdle != null && !maxIdle.isBlank()) {
            long idle = Long.parseLong(maxIdle.trim());
            builder.maxConnectionIdle(idle, TimeUnit.SECONDS);
            LOGGER.info("gRPC maxConnectionIdle={}s", idle);
        }
    }

    /**
     * Server SSL context on the JDK provider. With the JDK provider, Netty runs certificate validation (and so the
     * blocking OCSP query of the revocation trust manager) as a delegated task on the gRPC server executor rather
     * than on the event loop. The session timeout bounds how long a TLS session can be resumed without a full
     * handshake.
     */
    static SslContext buildSslContext(KeyManager keyManager, TrustManager trustManager) {
        long sessionTimeout =
                PropertyUtil.getPropertyLongValue(SERVER_TLS_SESSION_TIMEOUT, DEFAULT_TLS_SESSION_TIMEOUT);
        try {
            return GrpcSslContexts.configure(SslContextBuilder.forServer(keyManager), SslProvider.JDK)
                    .trustManager(trustManager)
                    .clientAuth(ClientAuth.REQUIRE)
                    .sessionTimeout(sessionTimeout)
                    .build();
        } catch (SSLException e) {
            throw new FederatorSslException("Failed to build the gRPC server SSL context", e);
        }
    }

    private static KeyManager[] loadKeyManagers() {
        String p12FilePath = PropertyUtil.getPropertyValue(SERVER_P12_FILE_PATH);
        String p12Password = PropertyUtil.getPropertyValue(SERVER_P12_PASSWORD);
        LOGGER.info("Using p12 file path: {}, p12 password is set: {}", p12FilePath, p12Password != null);
        return SSLUtils.createKeyManagerFromP12(p12FilePath, p12Password);
    }

    private static TrustManager[] loadTrustManagers() {
        String trustStoreFilePath = PropertyUtil.getPropertyValue(SERVER_TRUSTSTORE_FILE_PATH);
        String trustStorePassword = PropertyUtil.getPropertyValue(SERVER_TRUSTSTORE_PASSWORD);
        LOGGER.info(
                "Using truststore file path: {}, truststore password is set: {}",
                trustStoreFilePath,
                trustStorePassword != null);
        return SSLUtils.createTrustManager(trustStoreFilePath, trustStorePassword);
    }

    public void start() {
        try {
            LOGGER.info("GRPCServer starting");
            server.start();
        } catch (IOException e) {
            LOGGER.error("Exception encountered starting GRPC Server", e);
        }
    }

    /**
     * @return the port the server listens on (useful when started on port 0)
     */
    int getPort() {
        return server.getPort();
    }

    @ExcludeFromJacocoGeneratedReport
    @Override
    public void close() {
        try {
            LOGGER.info("GRPCServer close called");
            grpcFederatorService.close();
            server.shutdown().awaitTermination(30, TimeUnit.SECONDS);
            revocation.ifPresent(ServerRevocationSetup.Components::close);
            LOGGER.info("GRPCServer closed");
        } catch (InterruptedException e) {
            LOGGER.error("Exception occurred during shutdown", e);
            Thread.currentThread().interrupt();
        }
    }
}
