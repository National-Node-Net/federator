/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/**
 * Structured security logging and metrics for revocation decisions.
 * <p>
 * Log lines are key=value, e.g.
 * {@code event=revocation.decision component=producer phase=call peer_serial=4a1f issuer="CN=..." status=revoked
 * result=reject cause=revoked connection_id=10.0.0.5:51234/1a2b}.
 * A decision taken because no status was available (fail closed) is logged at ERROR with the
 * {@value #SECURITY_ALERT} marker and the key {@code alert=SECURITY_ALERT} in the line, so it can be alerted on with
 * any log pattern.
 */
public class RevocationAudit {

    public static final String SECURITY_ALERT = "SECURITY_ALERT";

    static final String CHECKS = "federator.revocation.checks";
    static final String CALLS_REJECTED = "federator.calls.rejected";
    static final String CONNECTIONS_TERMINATED = "federator.revocation.connections.terminated";
    static final String OCSP_DURATION = "federator.ocsp.request.duration";
    static final String OCSP_ERRORS = "federator.ocsp.errors";
    static final String CACHE_LOOKUPS = "federator.revocation.cache.lookups";

    private static final String TAG_PHASE = "phase";
    private static final String TAG_RESULT = "result";
    private static final String TAG_CAUSE = "cause";

    private static final Logger LOG = LoggerFactory.getLogger("RevocationAudit");
    private static final Marker ALERT = MarkerFactory.getMarker(SECURITY_ALERT);
    private static final String DECISION_FORMAT =
            "event=revocation.decision component={} phase={} peer_serial={} issuer=\"{}\" status={}"
                    + " result={} cause={} connection_id={}{} detail=\"{}\"";
    private static final String ALERT_FORMAT = DECISION_FORMAT + " alert=" + SECURITY_ALERT;

    /** Where the decision was taken. */
    public enum Phase {
        HANDSHAKE,
        CALL,
        RECHECK;

        public String tag() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** What happened to the peer. */
    public enum Result {
        ALLOW,
        REJECT,
        CLOSE;

        public String tag() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /**
     * The peer a decision applies to.
     *
     * @param serial       lowercase hex serial of the peer certificate
     * @param issuer       issuer DN of the peer certificate
     * @param connectionId remote address and TLS session id, or {@code "-"}
     * @param context      extra key=value pairs for the log line (e.g. {@code producer_id=... job_id=...}), or null
     */
    public record Peer(String serial, String issuer, String connectionId, String context) {

        public Peer(String serial, String issuer, String connectionId) {
            this(serial, issuer, connectionId, null);
        }
    }

    private final String component;
    private final MeterRegistry registry;
    /** Meters by name and tag values; the tag combinations are bounded (phase × result × cause × type). */
    private final ConcurrentHashMap<String, Meter> meters = new ConcurrentHashMap<>();

    /**
     * @param component {@code producer} or {@code consumer}
     * @param registry  meter registry the counters are registered with
     */
    public RevocationAudit(String component, MeterRegistry registry) {
        this.component = Objects.requireNonNull(component, "component");
        this.registry = Objects.requireNonNull(registry, "registry");
    }

    public MeterRegistry registry() {
        return registry;
    }

    /**
     * Records a decision.
     *
     * @param phase  where it was taken
     * @param peer   the peer
     * @param status {@code good}, {@code revoked}, {@code unknown} or {@code unavailable}
     * @param result allow, reject or close
     * @param cause  {@code revoked}, {@code unknown}, {@code unavailable} (with the failure type in {@code detail}),
     *               or {@code none} for an allowed good certificate
     * @param detail extra information, e.g. the responder failure; may be null
     */
    public void decision(Phase phase, Peer peer, String status, Result result, String cause, String detail) {
        counter(
                        CHECKS,
                        "Revocation decisions by check point and result",
                        TAG_PHASE,
                        phase.tag(),
                        TAG_RESULT,
                        result.tag(),
                        TAG_CAUSE,
                        cause)
                .increment();
        if (result == Result.REJECT) {
            counter(
                            CALLS_REJECTED,
                            "Handshakes and calls rejected by revocation checks",
                            TAG_PHASE,
                            phase.tag(),
                            TAG_CAUSE,
                            cause)
                    .increment();
        }
        log(phase, peer, status, result, cause, detail);
    }

    /**
     * Records a {@link RevocationVerdict}: {@code ALLOW} when allowed, otherwise {@code onReject}.
     */
    public void verdict(Phase phase, Peer peer, RevocationVerdict verdict, Result onReject, String detail) {
        decision(phase, peer, verdict.status(), verdict.allowed() ? Result.ALLOW : onReject, verdict.cause(), detail);
    }

    /**
     * Counts connections whose calls were all terminated after a re-check. The producer cannot close one connection
     * through the public gRPC API: the connection itself closes once idle ({@code server.maxConnectionIdle.seconds}).
     * The consumer shuts the channel to the producer down, which closes the connection at once.
     */
    public void connectionsTerminated(String cause, int connections) {
        counter(
                        CONNECTIONS_TERMINATED,
                        "Connections whose calls were all terminated by a revocation re-check",
                        TAG_CAUSE,
                        cause)
                .increment(connections);
    }

    /**
     * Records the duration of one OCSP check (all attempts) and, on failure, its type.
     */
    public void ocspRequest(Duration duration, OcspResponderException.Type failure) {
        String outcome = failure == null ? "success" : "failure";
        Timer timer = (Timer) meters.computeIfAbsent(OCSP_DURATION + "|" + outcome, k -> Timer.builder(OCSP_DURATION)
                .description("Duration of OCSP status checks including retries")
                .tag("role", component)
                .tag("outcome", outcome)
                .register(registry));
        timer.record(duration);
        if (failure != null) {
            counter(OCSP_ERRORS, "OCSP checks that gave no valid status, by failure type", "type", failure.tag())
                    .increment();
        }
    }

    /** A counter with the {@code role} tag plus the given tags, registered once and then reused. */
    private Counter counter(String name, String description, String... tags) {
        String key = name + "|" + String.join("|", tags);
        return (Counter) meters.computeIfAbsent(key, k -> Counter.builder(name)
                .description(description)
                .tag("role", component)
                .tags(tags)
                .register(registry));
    }

    /**
     * Counts status cache lookups, for the cache hit rate.
     */
    public void cacheLookup(boolean hit, String cacheType) {
        counter(CACHE_LOOKUPS, "Revocation status cache lookups", "cache", cacheType, TAG_RESULT, hit ? "hit" : "miss")
                .increment();
    }

    private void log(Phase phase, Peer peer, String status, Result result, String cause, String detail) {
        Object[] args = {
            component,
            phase.tag(),
            peer.serial(),
            peer.issuer(),
            status,
            result.tag(),
            cause,
            peer.connectionId(),
            peer.context() == null || peer.context().isBlank() ? "" : " " + peer.context(),
            detail == null ? "-" : detail
        };
        boolean unavailable = "unavailable".equals(cause);
        if (result == Result.ALLOW) {
            if (unavailable) {
                LOG.warn(DECISION_FORMAT, args);
            } else {
                LOG.debug(DECISION_FORMAT, args);
            }
        } else if (unavailable) {
            // the marker is for encoders/filters that use it; the key makes the alert visible with any log pattern
            LOG.error(ALERT, ALERT_FORMAT, args);
        } else {
            LOG.warn(DECISION_FORMAT, args);
        }
    }
}
