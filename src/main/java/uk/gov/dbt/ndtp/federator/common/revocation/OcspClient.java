/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import static uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException.Type.CIRCUIT_OPEN;
import static uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException.Type.HTTP_ERROR;
import static uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException.Type.INTERNAL_ERROR;
import static uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException.Type.INVALID_RESPONSE;
import static uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException.Type.MALFORMED_REQUEST;
import static uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException.Type.TIMEOUT;
import static uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException.Type.TRY_LATER;
import static uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException.Type.UNAUTHORIZED;
import static uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException.Type.UNREACHABLE;

import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import uk.gov.dbt.ndtp.federator.common.utils.ResilienceSupport;

/**
 * Asks the Management Node OCSP responder for the status of one certificate.
 * <p>
 * Each request carries a fresh 16-byte nonce (when {@code requireNonce}) and the bearer token the endpoint requires.
 * Attempts go through the {@code revocation.ocsp.resilience} retry and circuit breaker. The whole check, including
 * retries and the waits between them, never takes longer than {@code requestTimeout × maxAttempts}: every attempt is
 * limited to what is left of that budget, and no attempt starts once it is used up.
 */
public class OcspClient {

    static final String CONTENT_TYPE = "application/ocsp-request";
    static final String ACCEPT = "application/ocsp-response";
    static final String COMPONENT = "ocsp-responder";
    private static final int NONCE_BYTES = 16;
    /** Thread-safe; each {@code get()} returns a new, single-use digest calculator. */
    private static final DigestCalculatorProvider DIGESTS = digestProvider();

    private final HttpClient httpClient;
    private final OcspTokenProvider tokenProvider;
    private final OcspResponseVerifier verifier;
    private final ResilienceSupport.Policy policy;
    private final RevocationAudit audit;
    private final URI uri;
    private final Duration requestTimeout;
    private final Duration budget;
    private final boolean sendNonce;
    private final SecureRandom random = new SecureRandom();

    public OcspClient(
            HttpClient httpClient,
            OcspTokenProvider tokenProvider,
            OcspResponseVerifier verifier,
            ResilienceSupport.Policy policy,
            RevocationAudit audit,
            RevocationProperties properties) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.tokenProvider = Objects.requireNonNull(tokenProvider, "tokenProvider");
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.uri = properties.ocspUri();
        this.requestTimeout = properties.requestTimeout();
        this.budget = properties.checkBudget();
        this.sendNonce = properties.requireNonce();
    }

    /**
     * Builds the SHA-1 certificate ID of a certificate, as used in requests and cache keys.
     */
    public static CertificateID certificateId(X509Certificate certificate, X509Certificate issuer) {
        try {
            return new CertificateID(
                    DIGESTS.get(CertificateID.HASH_SHA1),
                    OcspResponseVerifier.holder(issuer),
                    certificate.getSerialNumber());
        } catch (OCSPException | OperatorCreationException e) {
            throw new IllegalStateException("Cannot build the OCSP certificate ID", e);
        }
    }

    private static DigestCalculatorProvider digestProvider() {
        try {
            return new JcaDigestCalculatorProviderBuilder().build();
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Digest calculator provider not available", e);
        }
    }

    /**
     * Queries the responder and verifies the answer.
     *
     * @param certificateId the certificate to ask about
     * @param issuer        its issuing CA, used to verify the response signer
     * @return the verified status
     * @throws OcspResponderException when no verified status could be obtained within the budget
     */
    public CertificateStatusEntry query(CertificateID certificateId, X509Certificate issuer) {
        long start = System.nanoTime();
        long deadline = start + budget.toNanos();
        String serial = CertificateKey.serialHex(certificateId.getSerialNumber());
        try {
            CertificateStatusEntry entry = policy.decorateAndExecute(
                    COMPONENT, "ocsp status", serial, () -> attempt(certificateId, issuer, deadline));
            audit.ocspRequest(Duration.ofNanos(System.nanoTime() - start), null);
            return entry;
        } catch (OcspResponderException e) {
            audit.ocspRequest(Duration.ofNanos(System.nanoTime() - start), e.getType());
            throw e;
        } catch (CallNotPermittedException e) {
            audit.ocspRequest(Duration.ofNanos(System.nanoTime() - start), CIRCUIT_OPEN);
            throw new OcspResponderException(CIRCUIT_OPEN, "OCSP circuit breaker is open", e);
        } catch (RuntimeException e) {
            audit.ocspRequest(Duration.ofNanos(System.nanoTime() - start), INVALID_RESPONSE);
            throw new OcspResponderException(INVALID_RESPONSE, "Unexpected OCSP failure: " + e, e);
        }
    }

    private CertificateStatusEntry attempt(CertificateID certificateId, X509Certificate issuer, long deadline) {
        Duration remaining = remaining(deadline);
        Extension nonce = sendNonce ? newNonce() : null;
        byte[] body = encodeRequest(certificateId, nonce);
        String token = tokenProvider.token(remaining);

        remaining = remaining(deadline);
        Duration timeout = remaining.compareTo(requestTimeout) < 0 ? remaining : requestTimeout;
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header("Content-Type", CONTENT_TYPE)
                .header("Accept", ACCEPT)
                .header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        HttpResponse<byte[]> response = send(request, timeout);
        checkHttpStatus(response.statusCode());

        OCSPResp ocspResponse = parse(response.body());
        checkResponseStatus(ocspResponse.getStatus());
        return verifier.verify(ocspResponse, certificateId, nonce, issuer);
    }

    private Duration remaining(long deadline) {
        long nanos = deadline - System.nanoTime();
        if (nanos <= 0) {
            throw new OcspResponderException(TIMEOUT, "OCSP check exceeded its budget of " + budget.toMillis() + " ms");
        }
        return Duration.ofNanos(nanos);
    }

    private HttpResponse<byte[]> send(HttpRequest request, Duration timeout) {
        CompletableFuture<HttpResponse<byte[]>> future =
                httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray());
        try {
            return future.get(Math.max(timeout.toMillis(), 1), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new OcspResponderException.Retryable(TIMEOUT, "OCSP request to " + uri + " timed out", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof java.net.http.HttpTimeoutException) {
                throw new OcspResponderException.Retryable(TIMEOUT, "OCSP request to " + uri + " timed out", cause);
            }
            throw new OcspResponderException.Retryable(
                    UNREACHABLE, "OCSP responder " + uri + " unreachable: " + cause, cause);
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new OcspResponderException(UNREACHABLE, "Interrupted during OCSP request", e);
        }
    }

    private void checkHttpStatus(int status) {
        if (status == 200) {
            return;
        }
        if (status == 401 || status == 403) {
            throw new OcspResponderException(
                    UNAUTHORIZED,
                    "OCSP responder answered HTTP " + status
                            + "; the federator client needs the check_certificate_status role");
        }
        if (status >= 500 || status == 429) {
            throw new OcspResponderException.Retryable(HTTP_ERROR, "OCSP responder answered HTTP " + status);
        }
        throw new OcspResponderException(HTTP_ERROR, "OCSP responder answered HTTP " + status);
    }

    private static OCSPResp parse(byte[] body) {
        try {
            return new OCSPResp(body);
        } catch (IOException | RuntimeException e) {
            throw new OcspResponderException(INVALID_RESPONSE, "OCSP response cannot be parsed", e);
        }
    }

    private static void checkResponseStatus(int status) {
        switch (status) {
            case OCSPResp.SUCCESSFUL -> {
                // verified next
            }
            case OCSPResp.TRY_LATER ->
                throw new OcspResponderException.Retryable(TRY_LATER, "OCSP responder: tryLater");
            case OCSPResp.INTERNAL_ERROR ->
                throw new OcspResponderException.Retryable(INTERNAL_ERROR, "OCSP responder: internalError");
            case OCSPResp.MALFORMED_REQUEST ->
                throw new OcspResponderException(MALFORMED_REQUEST, "OCSP responder: malformedRequest");
            case OCSPResp.UNAUTHORIZED ->
                throw new OcspResponderException(UNAUTHORIZED, "OCSP responder: unauthorized");
            default -> throw new OcspResponderException(INVALID_RESPONSE, "OCSP responder status " + status);
        }
    }

    private Extension newNonce() {
        byte[] value = new byte[NONCE_BYTES];
        random.nextBytes(value);
        try {
            return new Extension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(value).getEncoded());
        } catch (IOException e) {
            throw new IllegalStateException("Cannot encode OCSP nonce", e);
        }
    }

    private static byte[] encodeRequest(CertificateID certificateId, Extension nonce) {
        try {
            OCSPReqBuilder builder = new OCSPReqBuilder().addRequest(certificateId);
            if (nonce != null) {
                builder.setRequestExtensions(new Extensions(nonce));
            }
            OCSPReq request = builder.build();
            return request.getEncoded();
        } catch (OCSPException | IOException e) {
            throw new IllegalStateException("Cannot encode OCSP request", e);
        }
    }
}
