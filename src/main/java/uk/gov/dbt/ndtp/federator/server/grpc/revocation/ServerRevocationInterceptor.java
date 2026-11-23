/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.server.grpc.revocation;

import io.grpc.ForwardingServerCallListener;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import java.net.SocketAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import uk.gov.dbt.ndtp.federator.common.revocation.CertificateKey;
import uk.gov.dbt.ndtp.federator.common.revocation.ConnectionIds;
import uk.gov.dbt.ndtp.federator.common.revocation.IssuerResolver;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Peer;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Phase;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Result;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationChecker;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationDecision;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationTarget;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationVerdict;

/**
 * Checks the consumer's client certificate at the start of every call, before JWT validation, consumer
 * authorisation and OPA. Register it <b>last</b> in {@code ServerInterceptors.intercept(...)} so it runs first.
 * <ul>
 *     <li>{@code GOOD}: the call proceeds and is registered for re-checks in the {@link ActiveCallRegistry}.</li>
 *     <li>{@code REVOKED} / {@code UNKNOWN}: closed with {@code UNAUTHENTICATED}.</li>
 *     <li>No status available: closed with {@code UNAVAILABLE} when failing closed, otherwise allowed.</li>
 * </ul>
 */
public class ServerRevocationInterceptor implements ServerInterceptor {

    /** SSLSession value holding the resolved {@link RevocationTarget} of the peer. */
    static final String SESSION_TARGET = "uk.gov.dbt.ndtp.federator.revocation.target";

    private static final X509Certificate[] NO_CHAIN = new X509Certificate[0];

    private final RevocationChecker checker;
    private final ActiveCallRegistry registry;
    private final RevocationAudit audit;
    private final List<X509Certificate> trustedIssuers;
    private final boolean failClosed;

    public ServerRevocationInterceptor(
            RevocationChecker checker,
            ActiveCallRegistry registry,
            RevocationAudit audit,
            List<X509Certificate> trustedIssuers,
            boolean failClosed) {
        this.checker = Objects.requireNonNull(checker, "checker");
        this.registry = Objects.requireNonNull(registry, "registry");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.trustedIssuers = List.copyOf(trustedIssuers);
        this.failClosed = failClosed;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        SSLSession session = call.getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION);
        String connectionId = connectionId(call, session);

        RevocationTarget target = session == null ? null : sessionTarget(session);
        if (target == null) {
            X509Certificate[] chain = peerChain(session);
            if (session == null || chain.length == 0) {
                Peer peer = new Peer("-", "-", connectionId);
                audit.decision(Phase.CALL, peer, "none", Result.REJECT, "no_client_certificate", null);
                return reject(call, Status.UNAUTHENTICATED.withDescription("Client certificate required"));
            }
            Optional<X509Certificate> issuer = IssuerResolver.issuerOf(chain, trustedIssuers);
            if (issuer.isEmpty()) {
                Peer peer = new Peer(
                        CertificateKey.serialHex(chain[0].getSerialNumber()),
                        chain[0].getIssuerX500Principal().getName(),
                        connectionId);
                audit.decision(Phase.CALL, peer, "none", Result.REJECT, "issuer_not_found", null);
                return reject(call, Status.UNAUTHENTICATED.withDescription("Client certificate issuer not trusted"));
            }
            // the certificate chain of a TLS session never changes: resolve issuer and certificate ID once per session
            target = RevocationTarget.of(chain[0], issuer.get());
            session.putValue(SESSION_TARGET, target);
        }
        Peer peer = new Peer(target.serial(), target.issuerName(), connectionId);

        RevocationDecision decision = checker.check(target);
        RevocationVerdict verdict = RevocationVerdict.of(decision, failClosed);
        audit.verdict(Phase.CALL, peer, verdict, Result.REJECT, decision.detail());
        if (!verdict.allowed()) {
            return reject(call, verdict.rejection());
        }
        Instant recheckAt = decision instanceof RevocationDecision.Status verified
                ? checker.expiresAt(verified.entry())
                : checker.clock().instant().plus(ActiveCallRegistry.FAIL_OPEN_RETRY);

        RevocableServerCall<ReqT, RespT> revocable = new RevocableServerCall<>(call, connectionId, session);
        CertificateKey key = target.key();
        registry.register(target, revocable, recheckAt);

        ServerCall.Listener<ReqT> delegate;
        try {
            delegate = next.startCall(revocable, headers);
        } catch (RuntimeException e) {
            registry.unregister(key, revocable);
            throw e;
        }
        return new ForwardingServerCallListener.SimpleForwardingServerCallListener<>(delegate) {
            @Override
            public void onComplete() {
                registry.unregister(key, revocable);
                super.onComplete();
            }

            @Override
            public void onCancel() {
                registry.unregister(key, revocable);
                super.onCancel();
            }
        };
    }

    private static RevocationTarget sessionTarget(SSLSession session) {
        return session.getValue(SESSION_TARGET) instanceof RevocationTarget target ? target : null;
    }

    private static <ReqT, RespT> ServerCall.Listener<ReqT> reject(ServerCall<ReqT, RespT> call, Status status) {
        call.close(status, new Metadata());
        return new ServerCall.Listener<>() {};
    }

    /** The peer's X.509 chain, leaf first; empty when there is no session or no verified client certificate. */
    private static X509Certificate[] peerChain(SSLSession session) {
        if (session == null) {
            return NO_CHAIN;
        }
        try {
            Certificate[] certificates = session.getPeerCertificates();
            if (certificates == null || certificates.length == 0 || !(certificates[0] instanceof X509Certificate)) {
                return NO_CHAIN;
            }
            X509Certificate[] chain = new X509Certificate[certificates.length];
            for (int i = 0; i < certificates.length; i++) {
                chain[i] = (X509Certificate) certificates[i];
            }
            return chain;
        } catch (SSLPeerUnverifiedException | ClassCastException e) {
            return NO_CHAIN;
        }
    }

    /** {@code <remote address>/<TLS session id hex>}, identifying one TLS connection in logs. */
    static String connectionId(ServerCall<?, ?> call, SSLSession session) {
        SocketAddress remote = call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR);
        return ConnectionIds.of(remote == null ? null : remote.toString(), session);
    }
}
