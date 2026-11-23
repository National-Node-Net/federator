/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.server.grpc.revocation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import uk.gov.dbt.ndtp.federator.common.revocation.support.RevocationTestSupport;
import uk.gov.dbt.ndtp.federator.common.revocation.support.TestPki;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.exceptions.ConfigurationException;

class ServerRevocationSetupTest {

    private static final String LOGGER = ServerRevocationSetup.class.getName();

    @TempDir
    Path tempDir;

    private ListAppender<ILoggingEvent> logs;
    private TestPki pki;

    @BeforeEach
    void setUp() {
        logs = RevocationTestSupport.captureLogs(LOGGER);
        pki = new TestPki("Federation CA");
    }

    @AfterEach
    void tearDown() {
        RevocationTestSupport.detach(LOGGER, logs);
        PropertyUtil.clear();
    }

    private Optional<ServerRevocationSetup.Components> create(boolean mtls, AtomicBoolean clientCreated) {
        return ServerRevocationSetup.create(
                mtls,
                TestPki.trustManager(pki.caCertificate()),
                () -> {
                    clientCreated.set(true);
                    return HttpClient.newHttpClient();
                },
                RevocationTestSupport.tokenService(),
                new SimpleMeterRegistry());
    }

    private boolean warned(String text) {
        return logs.list.stream()
                .anyMatch(e ->
                        e.getLevel() == Level.WARN && e.getFormattedMessage().contains(text));
    }

    @Test
    void mtlsDisabledBuildsNothingAndWarns() {
        RevocationTestSupport.initProperties(tempDir, Map.of("management.node.base.url", "https://mn"));
        AtomicBoolean clientCreated = new AtomicBoolean();

        assertTrue(create(false, clientCreated).isEmpty());
        assertFalse(clientCreated.get());
        assertTrue(warned("inactive because mTLS is disabled"));
    }

    @Test
    void enforcementDisabledBuildsNothingAndWarns() {
        RevocationTestSupport.initProperties(
                tempDir, Map.of("management.node.base.url", "https://mn", "revocation.enforcement.enabled", "false"));
        AtomicBoolean clientCreated = new AtomicBoolean();

        assertTrue(create(true, clientCreated).isEmpty());
        assertFalse(clientCreated.get());
        assertTrue(warned("revocation.enforcement.enabled=false"));
    }

    @Test
    void enabledBuildsTheComponents() {
        RevocationTestSupport.initProperties(tempDir, Map.of("management.node.base.url", "https://mn"));
        AtomicBoolean clientCreated = new AtomicBoolean();

        Optional<ServerRevocationSetup.Components> components = create(true, clientCreated);

        assertTrue(components.isPresent());
        assertTrue(clientCreated.get());
        components.get().close();
    }

    @Test
    void transitionalSignerModeIsLogged() {
        RevocationTestSupport.initProperties(
                tempDir, Map.of("management.node.base.url", "https://mn", "revocation.ocsp.requireSignerEku", "false"));
        create(true, new AtomicBoolean()).ifPresent(ServerRevocationSetup.Components::close);
        assertTrue(warned("transitional"));
    }

    @Test
    void ttlAboveTheMaximumFailsStartup() {
        RevocationTestSupport.initProperties(
                tempDir, Map.of("management.node.base.url", "https://mn", "revocation.cache.ttl.seconds", "900"));
        assertThrows(ConfigurationException.class, () -> create(true, new AtomicBoolean()));
    }
}
