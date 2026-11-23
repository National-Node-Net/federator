/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.server.grpc.revocation;

import io.grpc.ForwardingServerCall;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.Status;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLSession;

/**
 * Server call that the revocation re-check can terminate from another thread.
 * <p>
 * gRPC server calls are not thread-safe, so sending, closing and flow control are serialised on one lock.
 * {@link #terminate(Status)} closes the call once; afterwards {@link #isCancelled()} is true and
 * {@link #sendMessage(Object)} throws {@code CANCELLED}, which stops the streaming conductor: its loop ends on
 * {@code isCancelled()} and {@code LimitedServerCallStreamObserver.onNext} fails, so no further data is sent.
 */
public final class RevocableServerCall<ReqT, RespT>
        extends ForwardingServerCall.SimpleForwardingServerCall<ReqT, RespT> {

    private final Object lock = new Object();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final String connectionId;
    private final SSLSession sslSession;
    private volatile boolean terminated;
    private final AtomicReference<Runnable> onClosed = new AtomicReference<>(() -> {});

    public RevocableServerCall(ServerCall<ReqT, RespT> delegate, String connectionId, SSLSession sslSession) {
        super(delegate);
        this.connectionId = connectionId;
        this.sslSession = sslSession;
    }

    /** Runs once, after the call is closed by the application or terminated. */
    void onClosed(Runnable callback) {
        this.onClosed.set(callback);
    }

    public String connectionId() {
        return connectionId;
    }

    /**
     * Closes the call with the given status unless it is already closed, and blocks further messages.
     * The TLS session is invalidated so the connection cannot be resumed without a full handshake.
     *
     * @return true when this call was closed by this method
     */
    public boolean terminate(Status status) {
        boolean closedNow;
        synchronized (lock) {
            terminated = true;
            closedNow = closed.compareAndSet(false, true);
            if (closedNow) {
                super.close(status, new Metadata());
            }
        }
        if (sslSession != null) {
            sslSession.invalidate();
        }
        if (closedNow) {
            onClosed.get().run();
        }
        return closedNow;
    }

    public boolean isTerminated() {
        return terminated;
    }

    @Override
    public void sendMessage(RespT message) {
        synchronized (lock) {
            if (terminated || closed.get()) {
                throw Status.CANCELLED
                        .withDescription("Call terminated: peer certificate failed the revocation check")
                        .asRuntimeException();
            }
            super.sendMessage(message);
        }
    }

    @Override
    public void sendHeaders(Metadata headers) {
        synchronized (lock) {
            if (!closed.get()) {
                super.sendHeaders(headers);
            }
        }
    }

    @Override
    public void request(int numMessages) {
        synchronized (lock) {
            if (!closed.get()) {
                super.request(numMessages);
            }
        }
    }

    @Override
    public void close(Status status, Metadata trailers) {
        boolean closedNow;
        synchronized (lock) {
            closedNow = closed.compareAndSet(false, true);
            if (closedNow) {
                super.close(status, trailers);
            }
        }
        if (closedNow) {
            onClosed.get().run();
        }
    }

    @Override
    public boolean isReady() {
        return !terminated && super.isReady();
    }

    @Override
    public boolean isCancelled() {
        return terminated || super.isCancelled();
    }
}
