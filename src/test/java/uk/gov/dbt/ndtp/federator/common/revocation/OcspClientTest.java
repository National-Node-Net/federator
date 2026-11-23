/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException.Type;
import uk.gov.dbt.ndtp.federator.common.revocation.support.RevocationTestSupport;
import uk.gov.dbt.ndtp.federator.common.revocation.support.StubOcspResponder;
import uk.gov.dbt.ndtp.federator.common.revocation.support.StubOcspResponder.Answer;
import uk.gov.dbt.ndtp.federator.common.revocation.support.StubOcspResponder.NonceMode;
import uk.gov.dbt.ndtp.federator.common.revocation.support.TestPki;
import uk.gov.dbt.ndtp.federator.common.service.idp.IdpTokenService;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;
import uk.gov.dbt.ndtp.federator.common.utils.ResilienceSupport;

class OcspClientTest {

    @TempDir
    Path tempDir;

    private TestPki pki;
    private StubOcspResponder stub;
    private X509Certificate leaf;
    private SimpleMeterRegistry meters;

    @BeforeEach
    void setUp() {
        RevocationTestSupport.initProperties(tempDir, Map.of());
        pki = new TestPki("Federation CA");
        stub = new StubOcspResponder(pki);
        leaf = pki.node("consumer-a").certificate();
        meters = new SimpleMeterRegistry();
    }

    @AfterEach
    void tearDown() {
        stub.close();
        PropertyUtil.clear();
    }

    private OcspClient client(boolean requireSignerEku, URI uri, IdpTokenService tokenService) {
        RevocationProperties properties = new RevocationProperties(
                true,
                uri,
                Duration.ofSeconds(1),
                2,
                true,
                requireSignerEku,
                RevocationTestSupport.SIGNER_CN,
                RevocationProperties.CacheType.MEMORY,
                Duration.ofSeconds(300),
                100);
        return new OcspClient(
                HttpClient.newHttpClient(),
                new OcspTokenProvider(tokenService, Clock.systemUTC()),
                new OcspResponseVerifier(true, requireSignerEku, RevocationTestSupport.SIGNER_CN, Clock.systemUTC()),
                new ResilienceSupport.Policy(
                        RevocationProperties.RESILIENCE_PREFIX, RevocationProperties.RESILIENCE_DEFAULTS),
                new RevocationAudit("producer", meters),
                properties);
    }

    private OcspClient client() {
        return client(true, stub.uri(), RevocationTestSupport.tokenService());
    }

    private CertificateStatusEntry query(OcspClient client) {
        return client.query(OcspClient.certificateId(leaf, pki.caCertificate()), pki.caCertificate());
    }

    private Type failure(OcspClient client) {
        return assertThrows(OcspResponderException.class, () -> query(client)).getType();
    }

    @Test
    void goodRevokedAndUnknownStatusesAreReturned() {
        OcspClient client = client();
        assertEquals(CertificateStatus.GOOD, query(client).status());

        stub.answer(leaf.getSerialNumber(), Answer.REVOKED);
        assertEquals(CertificateStatus.REVOKED, query(client).status());

        stub.answer(leaf.getSerialNumber(), Answer.UNKNOWN);
        assertEquals(CertificateStatus.UNKNOWN, query(client).status());
    }

    @Test
    void entryCarriesNextUpdateOfTheResponse() {
        CertificateStatusEntry entry = query(client());
        assertTrue(entry.nextUpdate() > entry.thisUpdate());
        assertEquals(Duration.ofMinutes(5).toMillis(), entry.nextUpdate() - entry.thisUpdate());
    }

    @Test
    void responseSignedByTheCaItselfIsAccepted() {
        stub.signWithCa();
        assertEquals(CertificateStatus.GOOD, query(client()).status());
    }

    @Test
    void invalidSignatureIsRejected() {
        stub.forgeSignature();
        assertEquals(Type.INVALID_RESPONSE, failure(client()));
    }

    @Test
    void mismatchedNonceIsRejected() {
        stub.nonce(NonceMode.WRONG);
        assertEquals(Type.INVALID_RESPONSE, failure(client()));
    }

    @Test
    void missingNonceIsRejectedWhenRequired() {
        stub.nonce(NonceMode.OMIT);
        assertEquals(Type.INVALID_RESPONSE, failure(client()));
    }

    @Test
    void certificateIdOfAnotherCertificateIsRejected() {
        stub.answerOtherSerial();
        assertEquals(Type.INVALID_RESPONSE, failure(client()));
    }

    @Test
    void signerWithoutOcspSigningEkuIsRejectedByDefault() {
        stub.signer(pki.signerWithoutOcspEku(RevocationTestSupport.SIGNER_CN));
        assertEquals(Type.INVALID_RESPONSE, failure(client()));
    }

    @Test
    void signerWithoutEkuIsAcceptedInTransitionalModeWithTheConfiguredCommonName() {
        stub.signer(pki.signerWithoutOcspEku(RevocationTestSupport.SIGNER_CN));
        OcspClient lax = client(false, stub.uri(), RevocationTestSupport.tokenService());
        assertEquals(CertificateStatus.GOOD, query(lax).status());
    }

    @Test
    void signerWithoutEkuAndAnotherCommonNameIsRejectedInTransitionalMode() {
        // e.g. a node certificate with a stolen key vouching for itself
        stub.signer(pki.node("consumer-b"));
        OcspClient lax = client(false, stub.uri(), RevocationTestSupport.tokenService());
        assertEquals(Type.INVALID_RESPONSE, failure(lax));
    }

    @Test
    void expiredSignerIsRejected() {
        stub.signer(pki.expiredOcspSigner(RevocationTestSupport.SIGNER_CN));
        assertEquals(Type.INVALID_RESPONSE, failure(client()));
    }

    @Test
    void signerIssuedByAnotherCaIsRejected() {
        stub.signer(new TestPki("Other CA").ocspSigner(RevocationTestSupport.SIGNER_CN));
        assertEquals(Type.INVALID_RESPONSE, failure(client()));
    }

    @Test
    void nextUpdateInThePastIsRejected() {
        stub.nextUpdateOffset(Duration.ofMinutes(-5));
        assertEquals(Type.INVALID_RESPONSE, failure(client()));
    }

    @Test
    void tryLaterIsRetriedThenReported() {
        stub.ocspStatus(OCSPResp.TRY_LATER);
        assertEquals(Type.TRY_LATER, failure(client()));
        assertEquals(2, stub.requests());
    }

    @Test
    void forbiddenIsNotRetried() {
        stub.httpStatus(403);
        assertEquals(Type.UNAUTHORIZED, failure(client()));
        assertEquals(1, stub.requests());
    }

    @Test
    void serverErrorIsRetried() {
        stub.httpStatus(500);
        assertEquals(Type.HTTP_ERROR, failure(client()));
        assertEquals(2, stub.requests());
    }

    @Test
    void slowResponderIsBoundedByRequestTimeoutTimesMaxAttempts() {
        stub.delay(Duration.ofSeconds(3));
        OcspClient client = client();
        long start = System.nanoTime();
        Type type = failure(client);
        Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
        assertEquals(Type.TIMEOUT, type);
        // budget = 1 s x 2 attempts; allow scheduling slack only
        assertTrue(elapsed.compareTo(Duration.ofMillis(2300)) < 0, "took " + elapsed);
    }

    @Test
    void unreachableResponderIsReported() {
        URI uri = stub.uri();
        stub.close();
        assertEquals(Type.UNREACHABLE, failure(client(true, uri, RevocationTestSupport.tokenService())));
    }

    @Test
    void tokenFailureIsReported() {
        IdpTokenService tokenService = mock(IdpTokenService.class);
        when(tokenService.fetchToken(any())).thenThrow(new IllegalStateException("idp down"));
        assertEquals(Type.TOKEN, failure(client(true, stub.uri(), tokenService)));
        assertEquals(0, stub.requests());
    }

    @Test
    void circuitBreakerOpensAfterRepeatedFailures() {
        stub.httpStatus(500);
        OcspClient client = client();
        for (int i = 0; i < 5; i++) {
            failure(client); // 2 attempts each: 10 failed calls fill the window
        }
        int requests = stub.requests();
        assertEquals(Type.CIRCUIT_OPEN, failure(client));
        assertEquals(requests, stub.requests());
    }

    @Test
    void concurrentQueriesAreVerifiedIndependently() throws Exception {
        OcspClient client = client();
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(8);
        try {
            java.util.List<java.util.concurrent.Future<CertificateStatusEntry>> results = new java.util.ArrayList<>();
            for (int i = 0; i < 32; i++) {
                X509Certificate certificate = pki.node("consumer-" + i).certificate();
                results.add(pool.submit(() ->
                        client.query(OcspClient.certificateId(certificate, pki.caCertificate()), pki.caCertificate())));
            }
            for (java.util.concurrent.Future<CertificateStatusEntry> result : results) {
                assertEquals(CertificateStatus.GOOD, result.get().status());
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void failuresAreCountedByType() {
        stub.httpStatus(403);
        failure(client());
        assertEquals(
                1.0,
                meters.get(RevocationAudit.OCSP_ERRORS)
                        .tag("type", "unauthorized")
                        .counter()
                        .count());
    }
}
