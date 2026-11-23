/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Peer;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Phase;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Result;

/**
 * Trust manager that adds a revocation check to the TLS handshake.
 * <p>
 * The PKIX trust manager built from the truststore validates the peer's chain first. The peer's leaf certificate is
 * then checked with the {@link RevocationChecker} (cache, or a blocking OCSP query bounded by
 * {@code requestTimeout × maxAttempts}). A revoked or unknown certificate always fails the handshake; no available
 * status fails it when {@code failClosed} is set.
 * <p>
 * On the gRPC server, Netty runs certificate validation as an SSLEngine delegated task on the server executor (with
 * the JDK SSL provider), so the OCSP query does not block the Netty event loop.
 */
public class OcspTrustManager extends X509ExtendedTrustManager {

    private final X509ExtendedTrustManager delegate;
    private final RevocationChecker checker;
    private final RevocationAudit audit;
    private final boolean failClosed;

    public OcspTrustManager(
            X509ExtendedTrustManager delegate, RevocationChecker checker, RevocationAudit audit, boolean failClosed) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.checker = Objects.requireNonNull(checker, "checker");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.failClosed = failClosed;
    }

    /**
     * @return the first {@link X509ExtendedTrustManager} of a trust manager factory's output
     */
    public static X509ExtendedTrustManager pkixDelegate(TrustManager[] trustManagers) {
        return Arrays.stream(trustManagers)
                .filter(X509ExtendedTrustManager.class::isInstance)
                .map(X509ExtendedTrustManager.class::cast)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No X509ExtendedTrustManager in the truststore"));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        delegate.checkClientTrusted(chain, authType, engine);
        checkRevocation(chain, peerAddress(engine));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        delegate.checkClientTrusted(chain, authType, socket);
        checkRevocation(chain, socket == null ? "-" : String.valueOf(socket.getRemoteSocketAddress()));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
        checkRevocation(chain, "-");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        delegate.checkServerTrusted(chain, authType, engine);
        checkRevocation(chain, peerAddress(engine));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        delegate.checkServerTrusted(chain, authType, socket);
        checkRevocation(chain, socket == null ? "-" : String.valueOf(socket.getRemoteSocketAddress()));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
        checkRevocation(chain, "-");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    private void checkRevocation(X509Certificate[] chain, String connectionId) throws CertificateException {
        X509Certificate leaf = chain[0];
        X509Certificate issuer = IssuerResolver.issuerOf(chain, List.of(getAcceptedIssuers()))
                .orElseThrow(() -> new CertificateException("Issuer of the peer certificate not found"));
        RevocationTarget target = RevocationTarget.of(leaf, issuer);
        Peer peer = new Peer(target.serial(), target.issuerName(), connectionId);

        RevocationDecision decision = checker.check(target);
        RevocationVerdict verdict = RevocationVerdict.of(decision, failClosed);
        audit.verdict(Phase.HANDSHAKE, peer, verdict, Result.REJECT, decision.detail());
        if (!verdict.allowed()) {
            throw new RevokedPeerCertificateException(peer.serial(), verdict.status());
        }
    }

    /**
     * The engine of the gRPC server does not know the peer address, so the TLS session id identifies the connection;
     * the call logs of the same connection carry the same session id after the address.
     */
    private static String peerAddress(SSLEngine engine) {
        if (engine == null) {
            return "-";
        }
        String address = engine.getPeerHost() == null ? null : engine.getPeerHost() + ":" + engine.getPeerPort();
        return ConnectionIds.of(address, engine.getHandshakeSession());
    }
}
