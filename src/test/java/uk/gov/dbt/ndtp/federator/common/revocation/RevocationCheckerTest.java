/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.math.BigInteger;
import java.net.http.HttpClient;
import java.nio.file.Path;
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

class RevocationCheckerTest {

    @TempDir
    Path tempDir;

    private TestPki pki;
    private StubOcspResponder stub;
    private RevocationChecker checker;
    private SimpleMeterRegistry meters;

    @BeforeEach
    void setUp() {
        RevocationTestSupport.initProperties(tempDir, Map.of());
        pki = new TestPki("Federation CA");
        stub = new StubOcspResponder(pki);
        meters = new SimpleMeterRegistry();
        RevocationProperties properties = RevocationTestSupport.properties(stub.uri(), Duration.ofSeconds(300));
        RevocationAudit audit = new RevocationAudit("producer", meters);
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
    }

    @AfterEach
    void tearDown() {
        stub.close();
        PropertyUtil.clear();
    }

    @Test
    void cachedStatusAvoidsANetworkCall() {
        X509Certificate leaf = pki.node("consumer-a").certificate();

        RevocationDecision first = checker.check(RevocationTarget.of(leaf, pki.caCertificate()));
        RevocationDecision second = checker.check(RevocationTarget.of(leaf, pki.caCertificate()));

        assertTrue(first.isGood());
        assertFalse(((RevocationDecision.Status) first).fromCache());
        assertTrue(((RevocationDecision.Status) second).fromCache());
        assertEquals(1, stub.requests());
        assertEquals(
                1.0,
                meters.get(RevocationAudit.CACHE_LOOKUPS)
                        .tag("result", "hit")
                        .counter()
                        .count());
    }

    @Test
    void revokedAndUnknownStatusesAreCached() {
        X509Certificate revoked = pki.node("consumer-r").certificate();
        stub.answer(revoked.getSerialNumber(), Answer.REVOKED);

        checker.check(RevocationTarget.of(revoked, pki.caCertificate()));
        RevocationDecision again = checker.check(RevocationTarget.of(revoked, pki.caCertificate()));

        assertEquals("revoked", again.statusTag());
        assertEquals(1, stub.requests());
    }

    @Test
    void failuresAreNotCached() {
        X509Certificate leaf = pki.node("consumer-a").certificate();
        stub.httpStatus(503);
        assertInstanceOf(
                RevocationDecision.ResponderFailure.class,
                checker.check(RevocationTarget.of(leaf, pki.caCertificate())));

        stub.httpStatus(200);
        assertTrue(checker.check(RevocationTarget.of(leaf, pki.caCertificate())).isGood());
    }

    @Test
    void refreshAsksTheResponderAgain() {
        X509Certificate leaf = pki.node("consumer-a").certificate();
        checker.check(RevocationTarget.of(leaf, pki.caCertificate()));
        stub.answer(leaf.getSerialNumber(), Answer.REVOKED);

        RevocationDecision refreshed = checker.refresh(RevocationTarget.of(leaf, pki.caCertificate()));

        assertEquals("revoked", refreshed.statusTag());
        assertEquals(2, stub.requests());
        assertEquals(
                "revoked",
                checker.check(RevocationTarget.of(leaf, pki.caCertificate())).statusTag());
    }

    @Test
    void serialWithLeadingZeroByteHasCanonicalKey() {
        BigInteger serial = new BigInteger("00ab01", 16);
        X509Certificate leaf = pki.node("consumer-z", serial).certificate();
        assertEquals(
                "ab01", RevocationTarget.of(leaf, pki.caCertificate()).key().serial());
    }
}
