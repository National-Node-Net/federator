/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation.support;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * OCSP responder for tests that follows the Management Node contract: {@code POST /api/v1/certificate/ocsp}, bearer
 * token required (HTTP 401 without), responder ID by key, signer certificate in {@code certs}, nonce echoed,
 * {@code nextUpdate = thisUpdate + 5 min}. Each behaviour can be broken on purpose.
 */
public final class StubOcspResponder implements AutoCloseable {

    public static final String PATH = "/api/v1/certificate/ocsp";

    /** How the nonce is answered. */
    public enum NonceMode {
        ECHO,
        OMIT,
        WRONG
    }

    /** Status answered for a serial. */
    public enum Answer {
        GOOD,
        REVOKED,
        UNKNOWN
    }

    private final TestPki pki;
    private final HttpServer server;
    private final Map<BigInteger, Answer> answers = new ConcurrentHashMap<>();
    private final AtomicInteger requests = new AtomicInteger();

    private volatile TestPki.Issued signer;
    private volatile boolean signWithCaKey;
    private volatile KeyPair forgedKey;
    private volatile NonceMode nonceMode = NonceMode.ECHO;
    private volatile boolean answerOtherSerial;
    private volatile Duration delay = Duration.ZERO;
    private volatile int httpStatus = 200;
    private volatile Integer ocspStatus;
    private volatile Duration nextUpdateOffset = Duration.ofMinutes(5);
    private volatile Answer defaultAnswer = Answer.GOOD;

    public StubOcspResponder(TestPki pki) {
        this.pki = pki;
        this.signer = pki.ocspSigner("ocsp-signer.management-node");
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        server.createContext(PATH, this::handle);
        server.setExecutor(Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "stub-ocsp");
            thread.setDaemon(true);
            return thread;
        }));
        server.start();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public URI uri() {
        return URI.create(baseUrl() + PATH);
    }

    public int requests() {
        return requests.get();
    }

    public StubOcspResponder answer(BigInteger serial, Answer answer) {
        answers.put(serial, answer);
        return this;
    }

    public StubOcspResponder defaultAnswer(Answer answer) {
        this.defaultAnswer = answer;
        return this;
    }

    public StubOcspResponder signer(TestPki.Issued signer) {
        this.signer = signer;
        return this;
    }

    /** Sign with the CA key itself (no delegated signer). */
    public StubOcspResponder signWithCa() {
        this.signWithCaKey = true;
        return this;
    }

    /** Keep the signer certificate and responder ID but sign with another key: invalid signature. */
    public StubOcspResponder forgeSignature() {
        this.forgedKey = TestPki.newKeyPair();
        return this;
    }

    public StubOcspResponder nonce(NonceMode mode) {
        this.nonceMode = mode;
        return this;
    }

    public StubOcspResponder answerOtherSerial() {
        this.answerOtherSerial = true;
        return this;
    }

    public StubOcspResponder delay(Duration delay) {
        this.delay = delay;
        return this;
    }

    public StubOcspResponder httpStatus(int status) {
        this.httpStatus = status;
        return this;
    }

    public StubOcspResponder ocspStatus(Integer status) {
        this.ocspStatus = status;
        return this;
    }

    public StubOcspResponder nextUpdateOffset(Duration offset) {
        this.nextUpdateOffset = offset;
        return this;
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            requests.incrementAndGet();
            if (!delay.isZero()) {
                Thread.sleep(delay.toMillis());
            }
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            if (authorization == null || !authorization.startsWith("Bearer ")) {
                exchange.sendResponseHeaders(401, -1);
                return;
            }
            if (httpStatus != 200) {
                exchange.sendResponseHeaders(httpStatus, -1);
                return;
            }
            byte[] body;
            try (InputStream in = exchange.getRequestBody()) {
                body = in.readAllBytes();
            }
            byte[] response = respond(body);
            exchange.getResponseHeaders().set("Content-Type", "application/ocsp-response");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(response);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private byte[] respond(byte[] body) throws Exception {
        if (ocspStatus != null) {
            return new OCSPRespBuilder().build(ocspStatus, null).getEncoded();
        }
        OCSPReq request = new OCSPReq(body);
        TestPki.Issued responder = signWithCaKey ? pki.ca() : signer;
        X509CertificateHolder responderCert =
                new X509CertificateHolder(responder.certificate().getEncoded());
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(
                responderCert.getSubjectPublicKeyInfo(),
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1));

        Instant thisUpdate = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant nextUpdate = thisUpdate.plus(nextUpdateOffset);
        for (Req req : request.getRequestList()) {
            CertificateID id = req.getCertID();
            if (answerOtherSerial) {
                id = CertificateID.deriveCertificateID(id, id.getSerialNumber().add(BigInteger.ONE));
            }
            builder.addResponse(
                    id, status(req.getCertID().getSerialNumber()), Date.from(thisUpdate), Date.from(nextUpdate), null);
        }

        Extension nonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (nonceMode == NonceMode.ECHO && nonce != null) {
            builder.setResponseExtensions(new Extensions(nonce));
        } else if (nonceMode == NonceMode.WRONG) {
            builder.setResponseExtensions(new Extensions(new Extension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                    false,
                    new DEROctetString(new byte[] {1, 2, 3, 4}).getEncoded())));
        }

        KeyPair signingKey = forgedKey != null ? forgedKey : responder.keyPair();
        X509CertificateHolder[] chain =
                signWithCaKey ? new X509CertificateHolder[0] : new X509CertificateHolder[] {responderCert};
        BasicOCSPResp basic = builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(signingKey.getPrivate()),
                chain,
                Date.from(thisUpdate));
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
    }

    private CertificateStatus status(BigInteger serial) {
        return switch (answers.getOrDefault(serial, defaultAnswer)) {
            case GOOD -> CertificateStatus.GOOD;
            case REVOKED -> new RevokedStatus(new Date(), CRLReason.keyCompromise);
            case UNKNOWN -> new UnknownStatus();
        };
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
