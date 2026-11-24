/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.server.grpc.revocation;

import io.grpc.Status;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import uk.gov.dbt.ndtp.federator.common.revocation.CertificateKey;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Peer;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Phase;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationAudit.Result;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationChecker;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationDecision;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationTarget;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationVerdict;

/**
 * Open calls per consumer certificate, re-checked when the certificate's cache entry expires.
 * <p>
 * The first call registered for a certificate schedules a re-check at the expiry of the status entry it was admitted
 * with. The re-check asks the OCSP responder again: {@code GOOD} schedules the next re-check at the new expiry;
 * {@code REVOKED} or {@code UNKNOWN} closes every open call of that certificate with {@code UNAUTHENTICATED}; no
 * available status closes them with {@code UNAVAILABLE} when failing closed, otherwise the re-check is retried after
 * {@link #FAIL_OPEN_RETRY}. Calls of other certificates are not affected. When the last call of a certificate ends,
 * its re-check is cancelled.
 */
@Slf4j
public class ActiveCallRegistry implements AutoCloseable {

    /** Delay before re-checking again after a responder failure when failing open. */
    static final Duration FAIL_OPEN_RETRY = Duration.ofSeconds(30);

    private static final class Tracked {
        private final RevocationTarget peer;
        private final Set<RevocableServerCall<?, ?>> calls = ConcurrentHashMap.newKeySet();
        private ScheduledFuture<?> recheck;
        private boolean removed;

        private Tracked(RevocationTarget peer) {
            this.peer = peer;
        }

        /** Schedules the first re-check, unless one exists or the entry was removed meanwhile. */
        private synchronized void scheduleFirst(Supplier<ScheduledFuture<?>> scheduling) {
            if (!removed && recheck == null) {
                recheck = scheduling.get();
            }
        }

        private synchronized void reschedule(Supplier<ScheduledFuture<?>> scheduling) {
            if (!removed) {
                recheck = scheduling.get();
            }
        }

        /** Marks the entry as removed from the map and cancels its pending re-check. */
        private synchronized void remove() {
            removed = true;
            if (recheck != null) {
                recheck.cancel(false);
            }
        }
    }

    private final ConcurrentHashMap<CertificateKey, Tracked> tracked = new ConcurrentHashMap<>();
    private final RevocationChecker checker;
    private final RevocationAudit audit;
    private final boolean failClosed;
    private final ScheduledExecutorService scheduler;

    public ActiveCallRegistry(RevocationChecker checker, RevocationAudit audit, boolean failClosed) {
        this(checker, audit, failClosed, newScheduler());
    }

    ActiveCallRegistry(
            RevocationChecker checker, RevocationAudit audit, boolean failClosed, ScheduledExecutorService scheduler) {
        this.checker = Objects.requireNonNull(checker, "checker");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.failClosed = failClosed;
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler");
    }

    private static ScheduledExecutorService newScheduler() {
        AtomicInteger counter = new AtomicInteger();
        return Executors.newScheduledThreadPool(2, runnable -> {
            Thread thread = new Thread(runnable, "revocation-recheck-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * Registers an open call. It is unregistered automatically when it closes.
     *
     * @param peer      the consumer certificate
     * @param call      the call
     * @param recheckAt when the certificate must be checked again (expiry of its status entry)
     */
    public void register(RevocationTarget peer, RevocableServerCall<?, ?> call, Instant recheckAt) {
        CertificateKey key = peer.key();
        call.onClosed(() -> unregister(key, call));
        Tracked entry = tracked.compute(key, (k, existing) -> {
            Tracked current = existing != null ? existing : new Tracked(peer);
            current.calls.add(call);
            return current;
        });
        // Scheduled after compute: until compute returns the map does not show a new entry, so a re-check due at once
        // could run, find nothing and never be scheduled again.
        entry.scheduleFirst(() -> schedule(key, recheckAt));
    }

    /**
     * Removes a call; cancels the re-check when it was the certificate's last call.
     */
    public void unregister(CertificateKey key, RevocableServerCall<?, ?> call) {
        tracked.computeIfPresent(key, (k, entry) -> {
            entry.calls.remove(call);
            if (entry.calls.isEmpty()) {
                entry.remove();
                return null;
            }
            return entry;
        });
    }

    /**
     * @return the number of open calls of a certificate
     */
    public int openCalls(CertificateKey key) {
        Tracked entry = tracked.get(key);
        return entry == null ? 0 : entry.calls.size();
    }

    private ScheduledFuture<?> schedule(CertificateKey key, Instant at) {
        long delayMillis =
                Math.max(0, Duration.between(checker.clock().instant(), at).toMillis());
        return scheduler.schedule(() -> recheck(key), delayMillis, TimeUnit.MILLISECONDS);
    }

    /** Runs on the scheduler at the expiry of the certificate's status entry. */
    void recheck(CertificateKey key) {
        Tracked entry = tracked.get(key);
        if (entry == null || entry.calls.isEmpty()) {
            return;
        }
        RevocationDecision decision = checker.refresh(entry.peer);
        RevocationVerdict verdict = RevocationVerdict.of(decision, failClosed);

        if (decision instanceof RevocationDecision.Status status && verdict.allowed()) {
            reschedule(key, checker.expiresAt(status.entry()));
            return;
        }
        if (verdict.allowed()) {
            // no status, failing open
            audit.verdict(
                    Phase.RECHECK, peerOf(entry.peer, connections(entry)), verdict, Result.CLOSE, decision.detail());
            reschedule(key, checker.clock().instant().plus(FAIL_OPEN_RETRY));
            return;
        }
        terminateAll(key, verdict, decision.detail());
    }

    private void reschedule(CertificateKey key, Instant at) {
        Tracked entry = tracked.get(key);
        if (entry != null) {
            entry.reschedule(() -> schedule(key, at));
        }
    }

    private void terminateAll(CertificateKey key, RevocationVerdict verdict, String detail) {
        Tracked entry = tracked.remove(key);
        if (entry == null) {
            return;
        }
        entry.remove();
        Status grpcStatus = verdict.rejection();
        List<RevocableServerCall<?, ?>> calls = List.copyOf(entry.calls);
        Set<String> connections =
                calls.stream().map(RevocableServerCall::connectionId).collect(Collectors.toSet());
        for (RevocableServerCall<?, ?> call : calls) {
            call.terminate(grpcStatus);
        }
        audit.verdict(
                Phase.RECHECK,
                peerOf(entry.peer, String.join(",", connections)),
                verdict,
                Result.CLOSE,
                calls.size() + " call(s) closed; " + detail);
        audit.connectionsTerminated(verdict.status(), connections.size());
    }

    private static String connections(Tracked entry) {
        return entry.calls.stream()
                .map(RevocableServerCall::connectionId)
                .distinct()
                .collect(Collectors.joining(","));
    }

    private static Peer peerOf(RevocationTarget peer, String connectionIds) {
        return new Peer(peer.serial(), peer.issuerName(), connectionIds);
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
        tracked.clear();
    }
}
