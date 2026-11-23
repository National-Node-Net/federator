/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.client.grpc.revocation;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.ForwardingClientCallListener;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import java.net.SocketAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import uk.gov.dbt.ndtp.federator.common.revocation.ActiveCallRegistry;
import uk.gov.dbt.ndtp.federator.common.revocation.ConnectionIds;
import uk.gov.dbt.ndtp.federator.common.revocation.IssuerResolver;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Peer;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Phase;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Result;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationDecision;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationEngine;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationTarget;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationVerdict;

/**
 * Checks the producer's server certificate for every call of one channel and registers the call for re-checks.
 * <p>
 * The TLS session of a call is known once the producer answers, so the check runs when the response headers arrive,
 * before any message of the call is passed on. (A fresh channel is built for every consumer job, so its TLS handshake
 * has already checked the same certificate; this check normally hits the cache.) A rejected call is cancelled with a
 * {@code PeerCertificateRejectedException} cause and its {@link RevocationGuard} is marked, so nothing it received is
 * written. An accepted call is registered in the {@link ActiveCallRegistry}; a later re-check that rejects the
 * certificate cancels it and shuts the channel down.
 * <p>
 * One interceptor serves one channel: {@link #attach(ManagedChannel)} it once the channel is built.
 */
public class ClientRevocationInterceptor implements ClientInterceptor {

    static final String SESSION_TARGET = "uk.gov.dbt.ndtp.federator.revocation.producer-target";

    private static final X509Certificate[] NO_CHAIN = new X509Certificate[0];

    private final RevocationEngine engine;
    private final AtomicReference<ManagedChannel> channel = new AtomicReference<>();

    public ClientRevocationInterceptor(RevocationEngine engine) {
        this.engine = Objects.requireNonNull(engine, "engine");
    }

    /** Sets the channel this interceptor serves, so a re-check can shut it down. */
    public ClientRevocationInterceptor attach(ManagedChannel managedChannel) {
        channel.set(managedChannel);
        return this;
    }

    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
            MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {
        // set by the stream loop around the stub call; a call made without one still gets checked
        RevocationGuard guard =
                Optional.ofNullable(RevocationGuard.CONTEXT_KEY.get()).orElseGet(() -> new RevocationGuard(null, null));
        ClientCall<ReqT, RespT> call = next.newCall(method, callOptions);
        return new ForwardingClientCall.SimpleForwardingClientCall<>(call) {
            private RevocableClientCall registered;

            @Override
            public void start(Listener<RespT> responseListener, Metadata headers) {
                super.start(
                        new ForwardingClientCallListener.SimpleForwardingClientCallListener<>(responseListener) {
                            @Override
                            public void onHeaders(Metadata responseHeaders) {
                                registered = checkAndRegister(call, guard);
                                super.onHeaders(responseHeaders);
                            }

                            @Override
                            public void onMessage(RespT message) {
                                if (guard.isRejected()) {
                                    return; // received after the rejection: discarded
                                }
                                super.onMessage(message);
                            }

                            @Override
                            public void onClose(Status status, Metadata trailers) {
                                if (registered != null) {
                                    registered.closed();
                                }
                                super.onClose(status, trailers);
                            }
                        },
                        headers);
            }
        };
    }

    /** Checks the producer certificate of the call; returns the registered call, or null when rejected. */
    private RevocableClientCall checkAndRegister(ClientCall<?, ?> call, RevocationGuard guard) {
        SSLSession session = call.getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION);
        SocketAddress remote = call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR);
        String connectionId = ConnectionIds.of(remote == null ? null : remote.toString(), session);

        RevocationTarget target = target(session);
        if (target == null) {
            Peer peer = new Peer("-", "-", connectionId, guard.context());
            RevocationVerdict verdict = new RevocationVerdict(false, "none", "no_server_certificate");
            engine.audit().decision(Phase.CALL, peer, "none", Result.REJECT, "no_server_certificate", null);
            reject(call, guard, "-", verdict);
            return null;
        }
        Peer peer = new Peer(target.serial(), target.issuerName(), connectionId, guard.context());
        RevocationDecision decision = engine.checker().check(target);
        RevocationVerdict verdict =
                RevocationVerdict.of(decision, engine.properties().failClosed());
        engine.audit().verdict(Phase.CALL, peer, verdict, Result.REJECT, decision.detail());
        if (!verdict.allowed()) {
            reject(call, guard, target.serial(), verdict);
            return null;
        }
        Instant recheckAt = decision instanceof RevocationDecision.Status verified
                ? engine.checker().expiresAt(verified.entry())
                : engine.checker().clock().instant().plus(ActiveCallRegistry.FAIL_OPEN_RETRY);
        RevocableClientCall revocable =
                new RevocableClientCall(call, channel.get(), guard, target.serial(), connectionId);
        engine.registry().register(target, revocable, recheckAt);
        return revocable;
    }

    private static void reject(ClientCall<?, ?> call, RevocationGuard guard, String serial, RevocationVerdict verdict) {
        guard.reject(serial, verdict);
        try {
            guard.ensureAccepted();
        } catch (RuntimeException rejected) {
            call.cancel("Producer certificate " + verdict.status(), rejected);
        }
    }

    /** The producer certificate and its issuer, resolved once per TLS session. */
    private RevocationTarget target(SSLSession session) {
        if (session == null) {
            return null;
        }
        if (session.getValue(SESSION_TARGET) instanceof RevocationTarget cached) {
            return cached;
        }
        X509Certificate[] chain = peerChain(session);
        if (chain.length == 0) {
            return null;
        }
        return IssuerResolver.issuerOf(chain, engine.trustedIssuers())
                .map(issuer -> {
                    RevocationTarget target = RevocationTarget.of(chain[0], issuer);
                    session.putValue(SESSION_TARGET, target);
                    return target;
                })
                .orElse(null);
    }

    /** The producer's X.509 chain, leaf first; empty when the session has no verified server certificate. */
    private static X509Certificate[] peerChain(SSLSession session) {
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
}
