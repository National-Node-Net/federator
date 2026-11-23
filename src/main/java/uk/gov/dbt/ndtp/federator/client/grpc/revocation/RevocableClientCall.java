/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.client.grpc.revocation;

import io.grpc.ClientCall;
import io.grpc.ManagedChannel;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationVerdict;
import uk.gov.dbt.ndtp.federator.common.revocation.TerminableCall;

/**
 * An open consumer call that a revocation re-check can end: the guard is marked rejected (so already received data is
 * discarded), the call is cancelled with a {@code PeerCertificateRejectedException} cause, and the channel to the
 * producer is shut down. {@link ClientCall#cancel} and {@link ManagedChannel#shutdownNow()} may be called from any
 * thread.
 */
final class RevocableClientCall implements TerminableCall {

    private final ClientCall<?, ?> call;
    private final ManagedChannel channel;
    private final RevocationGuard guard;
    private final String serial;
    private final String connectionId;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private volatile Runnable onClosed = () -> {};

    RevocableClientCall(
            ClientCall<?, ?> call, ManagedChannel channel, RevocationGuard guard, String serial, String connectionId) {
        this.call = Objects.requireNonNull(call, "call");
        this.channel = channel;
        this.guard = Objects.requireNonNull(guard, "guard");
        this.serial = serial;
        this.connectionId = connectionId;
    }

    @Override
    public String connectionId() {
        return connectionId;
    }

    @Override
    public String context() {
        return guard.context();
    }

    @Override
    public boolean terminate(RevocationVerdict verdict) {
        if (!closed.compareAndSet(false, true)) {
            return false;
        }
        guard.reject(serial, verdict);
        call.cancel("Producer certificate " + verdict.status(), guardRejection());
        if (channel != null) {
            channel.shutdownNow();
        }
        onClosed.run();
        return true;
    }

    private Throwable guardRejection() {
        try {
            guard.ensureAccepted();
            return null;
        } catch (RuntimeException rejected) {
            return rejected;
        }
    }

    /** Called when the call ends on its own. */
    void closed() {
        if (closed.compareAndSet(false, true)) {
            onClosed.run();
        }
    }

    @Override
    public void onClosed(Runnable callback) {
        this.onClosed = callback;
    }
}
