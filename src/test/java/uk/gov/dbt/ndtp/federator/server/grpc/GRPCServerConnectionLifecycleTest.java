/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.server.grpc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;
import uk.gov.dbt.ndtp.federator.common.revocation.support.RevocationTestSupport;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;

class GRPCServerConnectionLifecycleTest {

    @TempDir
    Path tempDir;

    @AfterEach
    void tearDown() {
        PropertyUtil.clear();
    }

    private static NettyServerBuilder builder() {
        return mock(NettyServerBuilder.class, Mockito.RETURNS_SELF);
    }

    @Test
    void revocationActiveAppliesMaxConnectionAgeAndIdleWithoutAGraceKill() {
        RevocationTestSupport.initProperties(tempDir, Map.of());
        NettyServerBuilder builder = builder();

        GRPCServer.configureConnectionLifecycle(builder, true);

        verify(builder).maxConnectionAge(1800, TimeUnit.SECONDS);
        verify(builder, never()).maxConnectionAgeGrace(anyLong(), any());
        verify(builder).maxConnectionIdle(60, TimeUnit.SECONDS);
    }

    @Test
    void emptyPlaceholderValuesCountAsNotSet() {
        // what ${SERVER_MAXCONNECTIONAGE_SECONDS:} etc. resolve to when the environment variables are not set
        RevocationTestSupport.initProperties(
                tempDir,
                Map.of(
                        "server.maxConnectionAge.seconds", "",
                        "server.maxConnectionAgeGrace.seconds", "",
                        "server.maxConnectionIdle.seconds", ""));
        NettyServerBuilder active = builder();
        NettyServerBuilder inactive = builder();

        GRPCServer.configureConnectionLifecycle(active, true);
        GRPCServer.configureConnectionLifecycle(inactive, false);

        verify(active).maxConnectionAge(1800, TimeUnit.SECONDS);
        verify(active, never()).maxConnectionAgeGrace(anyLong(), any());
        verify(active).maxConnectionIdle(60, TimeUnit.SECONDS);
        verify(inactive, never()).maxConnectionAge(anyLong(), any());
        verify(inactive, never()).maxConnectionIdle(anyLong(), any());
    }

    @Test
    void revocationInactiveAppliesNothingByDefault() {
        RevocationTestSupport.initProperties(tempDir, Map.of());
        NettyServerBuilder builder = builder();

        GRPCServer.configureConnectionLifecycle(builder, false);

        verify(builder, never()).maxConnectionAge(anyLong(), any());
        verify(builder, never()).maxConnectionIdle(anyLong(), any());
    }

    @Test
    void explicitValuesAreApplied() {
        RevocationTestSupport.initProperties(
                tempDir,
                Map.of(
                        "server.maxConnectionAge.seconds", "600",
                        "server.maxConnectionAgeGrace.seconds", "120",
                        "server.maxConnectionIdle.seconds", "300"));
        NettyServerBuilder builder = builder();

        GRPCServer.configureConnectionLifecycle(builder, false);

        verify(builder).maxConnectionAge(600, TimeUnit.SECONDS);
        verify(builder).maxConnectionAgeGrace(120, TimeUnit.SECONDS);
        verify(builder).maxConnectionIdle(300, TimeUnit.SECONDS);
    }
}
