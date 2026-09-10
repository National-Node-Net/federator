/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the Department for Business and Trade (UK) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.server.grpc;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import io.grpc.Server;
import io.grpc.ServerBuilder;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.dbt.ndtp.federator.common.service.idp.IdpTokenService;
import uk.gov.dbt.ndtp.federator.common.utils.GRPCUtils;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.common.utils.SSLUtils;

class GRPCServerTest {

    @Test
    void testGRPCServerWithInsecureServer() {
        Properties mockNestedProps = mock(Properties.class);
        when(mockNestedProps.getProperty(anyString())).thenReturn("test");

        try (MockedStatic<PropertyUtil> propertyUtilMockedStatic = mockStatic(PropertyUtil.class);
                MockedStatic<SSLUtils> sslUtilsMockedStatic = mockStatic(SSLUtils.class);
                MockedStatic<ServerBuilder> serverBuilderMockedStatic = mockStatic(ServerBuilder.class);
                MockedStatic<GRPCUtils> grpcUtilsMockedStatic = mockStatic(GRPCUtils.class)) {

            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertyBooleanValue(GRPCServer.SERVER_MTLS_ENABLED, GRPCServer.FALSE))
                    .thenReturn(false);
            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertyIntValue(GRPCServer.SERVER_PORT, GRPCServer.DEFAULT_PORT))
                    .thenReturn(8080);
            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertyIntValue(GRPCServer.SERVER_KEEP_ALIVE_TIME, GRPCServer.FIVE))
                    .thenReturn(5);
            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertyIntValue(GRPCServer.SERVER_KEEP_ALIVE_TIMEOUT, GRPCServer.ONE))
                    .thenReturn(1);
            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertiesFromFilePath(any()))
                    .thenReturn(mockNestedProps);

            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertyValue(anyString(), anyString()))
                    .thenAnswer(invocation -> invocation.getArgument(1));

            SSLContext mockSslContext = mock(SSLContext.class);

            sslUtilsMockedStatic
                    .when(() -> SSLUtils.createSSLContext(anyString(), anyString(), anyString(), anyString()))
                    .thenReturn(mockSslContext);

            ServerBuilder<?> serverBuilder = mock(ServerBuilder.class, Mockito.RETURNS_SELF);
            Server mockServer = mock(Server.class);
            when(serverBuilder.build()).thenReturn(mockServer);
            serverBuilderMockedStatic
                    .when(() -> ServerBuilder.forPort(any(Integer.class)))
                    .thenReturn(serverBuilder);

            IdpTokenService mockIdpTokenService = mock(IdpTokenService.class);
            grpcUtilsMockedStatic.when(GRPCUtils::createIdpTokenService).thenReturn(mockIdpTokenService);

            Set<String> sharedHeaders = new HashSet<>();

            GRPCServer server = new GRPCServer(sharedHeaders);
            assertNotNull(server);
        }
    }

    @Test
    void testGRPCServerWithSecureServer() {
        Properties mockNestedProps = mock(Properties.class);
        when(mockNestedProps.getProperty(anyString())).thenReturn("test");

        try (MockedStatic<PropertyUtil> propertyUtilMockedStatic = mockStatic(PropertyUtil.class);
                MockedStatic<SSLUtils> sslUtilsMockedStatic = mockStatic(SSLUtils.class);
                MockedStatic<ServerBuilder> serverBuilderMockedStatic = mockStatic(ServerBuilder.class);
                MockedStatic<GRPCUtils> grpcUtilsMockedStatic = mockStatic(GRPCUtils.class)) {

            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertyBooleanValue(GRPCServer.SERVER_MTLS_ENABLED, GRPCServer.FALSE))
                    .thenReturn(true);
            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertyIntValue(GRPCServer.SERVER_PORT, GRPCServer.DEFAULT_PORT))
                    .thenReturn(8080);
            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertyIntValue(GRPCServer.SERVER_KEEP_ALIVE_TIME, GRPCServer.FIVE))
                    .thenReturn(5);
            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertyIntValue(GRPCServer.SERVER_KEEP_ALIVE_TIMEOUT, GRPCServer.ONE))
                    .thenReturn(1);
            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertyValue(any()))
                    .thenReturn("dummy");
            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertiesFromFilePath(any()))
                    .thenReturn(mockNestedProps);
            propertyUtilMockedStatic
                    .when(() -> PropertyUtil.getPropertyValue(anyString(), anyString()))
                    .thenAnswer(invocation -> invocation.getArgument(1));

            X509KeyManager mockKeyManager = mock(X509KeyManager.class);
            X509TrustManager mockTrustManager = mock(X509TrustManager.class);

            sslUtilsMockedStatic
                    .when(() -> SSLUtils.createKeyManagerFromP12(anyString(), anyString()))
                    .thenReturn(new KeyManager[] {mockKeyManager});
            sslUtilsMockedStatic
                    .when(() -> SSLUtils.createTrustManager(anyString(), anyString()))
                    .thenReturn(new TrustManager[] {mockTrustManager});
            SSLContext mockSslContext = mock(SSLContext.class);

            sslUtilsMockedStatic
                    .when(() -> SSLUtils.createSSLContext(anyString(), anyString(), anyString(), anyString()))
                    .thenReturn(mockSslContext);

            ServerBuilder<?> serverBuilder = mock(ServerBuilder.class, Mockito.RETURNS_SELF);
            Server mockServer = mock(Server.class);
            when(serverBuilder.build()).thenReturn(mockServer);
            serverBuilderMockedStatic
                    .when(() -> ServerBuilder.forPort(any(Integer.class)))
                    .thenReturn(serverBuilder);

            IdpTokenService mockIdpTokenService = mock(IdpTokenService.class);
            grpcUtilsMockedStatic.when(GRPCUtils::createIdpTokenService).thenReturn(mockIdpTokenService);

            Set<String> sharedHeaders = new HashSet<>();

            GRPCServer server = new GRPCServer(sharedHeaders);
            assertNotNull(server);
        }
    }
}
