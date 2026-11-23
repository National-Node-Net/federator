/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import uk.gov.dbt.ndtp.federator.common.revocation.support.RevocationTestSupport;
import uk.gov.dbt.ndtp.federator.common.revocation.support.StubOcspResponder;
import uk.gov.dbt.ndtp.federator.common.revocation.support.StubOcspResponder.Answer;
import uk.gov.dbt.ndtp.federator.common.revocation.support.TestPki;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.common.utils.ResilienceSupport;

class OcspTrustManagerTest {

    private static final String AUTH_TYPE = "ECDHE_ECDSA";

    @TempDir
    Path tempDir;

    private TestPki pki;
    private StubOcspResponder stub;
    private RevocationChecker checker;
    private RevocationAudit audit;
    private SimpleMeterRegistry meters;
    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void setUp() {
        RevocationTestSupport.initProperties(tempDir, Map.of());
        pki = new TestPki("Federation CA");
        stub = new StubOcspResponder(pki);
        meters = new SimpleMeterRegistry();
        audit = new RevocationAudit("producer", meters);
        RevocationProperties properties = RevocationTestSupport.properties(stub.uri(), Duration.ofSeconds(300));
        OcspClient client = new OcspClient(
                HttpClient.newHttpClient(),
                new OcspTokenProvider(RevocationTestSupport.tokenService(), Clock.systemUTC()),
                new OcspResponseVerifier(true, true, RevocationTestSupport.SIGNER_CN, Clock.systemUTC()),
                new ResilienceSupport.Policy(
                        RevocationProperties.RESILIENCE_PREFIX, RevocationProperties.RESILIENCE_DEFAULTS),
                audit,
                properties);
        checker = new RevocationChecker(
                client,
                new CaffeineRevocationStatusCache(100, properties.cacheTtl(), Clock.systemUTC(), meters),
                audit,
                properties.cacheTtl(),
                Clock.systemUTC());
        logs = RevocationTestSupport.captureLogs("RevocationAudit");
    }

    @AfterEach
    void tearDown() {
        RevocationTestSupport.detach("RevocationAudit", logs);
        stub.close();
        PropertyUtil.clear();
    }

    private OcspTrustManager trustManager(boolean failClosed) {
        return new OcspTrustManager(TestPki.trustManager(pki.caCertificate()), checker, audit, failClosed);
    }

    private X509Certificate[] chain(TestPki.Issued issued) {
        return new X509Certificate[] {issued.certificate(), pki.caCertificate()};
    }

    @Test
    void goodCertificatePasses() {
        assertDoesNotThrow(() -> trustManager(true).checkClientTrusted(chain(pki.node("consumer-a")), AUTH_TYPE));
        assertEquals(1, stub.requests());
    }

    @Test
    void leafOnlyChainUsesTheIssuerFromTheTruststore() {
        X509Certificate[] leafOnly = {pki.node("consumer-a").certificate()};
        assertDoesNotThrow(() -> trustManager(true).checkClientTrusted(leafOnly, AUTH_TYPE));
    }

    @Test
    void revokedCertificateFailsTheHandshake() {
        TestPki.Issued revoked = pki.node("consumer-r");
        stub.answer(revoked.certificate().getSerialNumber(), Answer.REVOKED);

        assertThrows(
                CertificateException.class, () -> trustManager(true).checkClientTrusted(chain(revoked), AUTH_TYPE));
        assertEquals(
                1.0,
                meters.get(RevocationAudit.CALLS_REJECTED)
                        .tag("phase", "handshake")
                        .tag("cause", "revoked")
                        .counter()
                        .count());
        assertTrue(logs.list.stream()
                .anyMatch(e -> e.getLevel() == Level.WARN
                        && e.getFormattedMessage().contains("phase=handshake")
                        && e.getFormattedMessage().contains("status=revoked")
                        && e.getFormattedMessage().contains("result=reject")));
    }

    @Test
    void unknownCertificateFailsTheHandshake() {
        TestPki.Issued unknown = pki.node("consumer-u");
        stub.answer(unknown.certificate().getSerialNumber(), Answer.UNKNOWN);
        assertThrows(
                CertificateException.class, () -> trustManager(true).checkClientTrusted(chain(unknown), AUTH_TYPE));
    }

    @Test
    void untrustedChainFailsBeforeAnyOcspRequest() {
        TestPki other = new TestPki("Other CA");
        X509Certificate[] foreign = {other.node("intruder").certificate(), other.caCertificate()};
        assertThrows(CertificateException.class, () -> trustManager(true).checkClientTrusted(foreign, AUTH_TYPE));
        assertEquals(0, stub.requests());
    }

    @Test
    void unavailableStatusFailsClosedWithAnAlert() {
        stub.httpStatus(503);
        assertThrows(CertificateException.class, () -> trustManager(true)
                .checkClientTrusted(chain(pki.node("consumer-a")), AUTH_TYPE));
        assertTrue(logs.list.stream()
                .anyMatch(e -> e.getLevel() == Level.ERROR
                        && e.getMarkerList() != null
                        && e.getMarkerList().stream().anyMatch(m -> RevocationAudit.SECURITY_ALERT.equals(m.getName()))
                        && e.getFormattedMessage().contains("cause=unavailable")));
    }

    @Test
    void unavailableStatusIsAllowedWhenFailingOpen() {
        stub.httpStatus(503);
        assertDoesNotThrow(() -> trustManager(false).checkClientTrusted(chain(pki.node("consumer-a")), AUTH_TYPE));
    }

    @Test
    void engineAndSocketVariantsAreChecked() {
        TestPki.Issued revoked = pki.node("consumer-r");
        stub.answer(revoked.certificate().getSerialNumber(), Answer.REVOKED);
        OcspTrustManager trustManager = trustManager(true);

        assertThrows(
                CertificateException.class,
                () -> trustManager.checkClientTrusted(chain(revoked), AUTH_TYPE, (javax.net.ssl.SSLEngine) null));
        assertThrows(
                CertificateException.class,
                () -> trustManager.checkClientTrusted(chain(revoked), AUTH_TYPE, (java.net.Socket) null));
        assertThrows(
                CertificateException.class,
                () -> trustManager.checkServerTrusted(chain(revoked), AUTH_TYPE, (java.net.Socket) null));
        assertDoesNotThrow(() ->
                trustManager.checkClientTrusted(chain(pki.node("consumer-a")), AUTH_TYPE, (java.net.Socket) null));
        assertTrue(trustManager.getAcceptedIssuers().length > 0);
        assertThrows(
                IllegalArgumentException.class, () -> OcspTrustManager.pkixDelegate(new javax.net.ssl.TrustManager[0]));
    }

    @Test
    void serverCertificatesAreCheckedToo() {
        TestPki.Issued revoked = pki.node("producer-r");
        stub.answer(revoked.certificate().getSerialNumber(), Answer.REVOKED);
        assertThrows(
                CertificateException.class, () -> trustManager(true).checkServerTrusted(chain(revoked), AUTH_TYPE));
    }
}
