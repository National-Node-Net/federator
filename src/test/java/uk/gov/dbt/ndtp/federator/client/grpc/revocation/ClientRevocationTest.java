/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.client.grpc.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import uk.gov.dbt.ndtp.federator.common.revocation.PeerCertificateRejectedException;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationVerdict;
import uk.gov.dbt.ndtp.federator.common.revocation.support.RevocationTestSupport;
import uk.gov.dbt.ndtp.federator.common.revocation.support.TestPki;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.exceptions.ConfigurationException;

class ClientRevocationTest {

    private static final String LOGGER = ClientRevocation.class.getName();

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
        ClientRevocation.close();
        RevocationTestSupport.detach(LOGGER, logs);
        PropertyUtil.clear();
    }

    private boolean install(AtomicBoolean clientCreated) {
        return ClientRevocation.install(
                        () -> TestPki.trustManager(pki.caCertificate()),
                        () -> {
                            clientCreated.set(true);
                            return HttpClient.newHttpClient();
                        },
                        RevocationTestSupport::tokenService,
                        new SimpleMeterRegistry())
                .isPresent();
    }

    private boolean warned(String text) {
        return logs.list.stream()
                .anyMatch(e ->
                        e.getLevel() == Level.WARN && e.getFormattedMessage().contains(text));
    }

    @Test
    void mtlsDisabledBuildsNothingAndWarns() {
        RevocationTestSupport.initProperties(
                tempDir, Map.of("management.node.base.url", "https://mn", "client.tlsEnabled", "false"));
        AtomicBoolean clientCreated = new AtomicBoolean();

        assertFalse(install(clientCreated));
        assertFalse(clientCreated.get());
        assertTrue(ClientRevocation.engine().isEmpty());
        assertTrue(warned("inactive because mTLS is disabled"));
    }

    @Test
    void enforcementDisabledBuildsNothingAndWarns() {
        RevocationTestSupport.initProperties(
                tempDir, Map.of("management.node.base.url", "https://mn", "revocation.enforcement.enabled", "false"));
        assertFalse(install(new AtomicBoolean()));
        assertTrue(warned("revocation.enforcement.enabled=false"));
    }

    @Test
    void enabledByDefault() {
        RevocationTestSupport.initProperties(tempDir, Map.of("management.node.base.url", "https://mn"));
        AtomicBoolean clientCreated = new AtomicBoolean();

        assertTrue(install(clientCreated));
        assertTrue(clientCreated.get());
        assertTrue(ClientRevocation.engine().isPresent());

        ClientRevocation.close();
        assertTrue(ClientRevocation.engine().isEmpty());
    }

    @Test
    void invalidTtlFailsStartup() {
        RevocationTestSupport.initProperties(
                tempDir, Map.of("management.node.base.url", "https://mn", "revocation.cache.ttl.seconds", "601"));
        AtomicBoolean warned = new AtomicBoolean();
        assertThrows(ConfigurationException.class, () -> install(warned));
    }

    @Test
    void sessionTimeoutIsConfigurableAndEmptyMeansDefault() {
        RevocationTestSupport.initProperties(tempDir, Map.of("client.tlsSessionTimeout.seconds", ""));
        assertEquals(300, RevocationCheckedChannels.sessionTimeoutSeconds());

        RevocationTestSupport.initProperties(tempDir, Map.of("client.tlsSessionTimeout.seconds", "120"));
        assertEquals(120, RevocationCheckedChannels.sessionTimeoutSeconds());
        long applied = RevocationCheckedChannels.sslContext(
                        pki.keyManagerFactory(pki.node("consumer")).getKeyManagers()[0],
                        TestPki.trustManager(pki.caCertificate()),
                        120)
                .sessionContext()
                .getSessionTimeout();
        assertEquals(120, applied);
    }

    @Test
    void guardBlocksDataOnceRejected() {
        RevocationGuard guard = new RevocationGuard("ProducerA", "topic");
        guard.ensureAccepted();
        assertFalse(guard.isRejected());

        guard.reject("4a1f", new RevocationVerdict(false, "revoked", "revoked"));
        guard.reject("4a1f", new RevocationVerdict(false, "unknown", "unknown")); // first rejection wins

        assertTrue(guard.isRejected());
        PeerCertificateRejectedException rejected =
                assertThrows(PeerCertificateRejectedException.class, guard::ensureAccepted);
        assertEquals("revoked", rejected.getVerdict().status());
        assertTrue(guard.context().startsWith("producer_id=ProducerA topic=topic job_id="));
    }
}
