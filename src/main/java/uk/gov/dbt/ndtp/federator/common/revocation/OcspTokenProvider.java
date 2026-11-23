/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.LongSupplier;
import lombok.extern.slf4j.Slf4j;
import uk.gov.dbt.ndtp.federator.common.service.idp.IdpTokenService;

/**
 * Bearer token for the Management Node OCSP endpoint, obtained within the time budget of a revocation check.
 * <p>
 * {@link IdpTokenService#fetchToken()} retries with the {@code management.node.resilience} policy (minutes of
 * backoff), which is far too slow for a TLS handshake. This class calls {@link IdpTokenService#fetchToken(String)}
 * (no retry, Redis-cached token) on a background thread, keeps the token in memory until shortly before it expires,
 * and waits for a new one at most for the time the check has left. Concurrent checks share one token request.
 * <p>
 * A token request that has not finished after {@link #MAX_REQUEST_AGE} is abandoned (its thread is interrupted) and
 * the next check starts a new one, so an IdP that hangs cannot block revocation checks for good.
 */
@Slf4j
public class OcspTokenProvider implements AutoCloseable {

    /** A token is renewed when it expires within this margin. */
    static final Duration EXPIRY_MARGIN = Duration.ofSeconds(30);

    /** Lifetime assumed for a token whose expiry cannot be read. */
    static final Duration UNKNOWN_EXPIRY = Duration.ofSeconds(60);

    /** A token request still running after this time is abandoned and replaced. */
    static final Duration MAX_REQUEST_AGE = IdpTokenService.TOKEN_REQUEST_TIMEOUT.plusSeconds(5);

    private record CachedToken(String value, Instant expiresAt) {}

    private record Request(Future<String> future, long startedNanos) {}

    private final IdpTokenService tokenService;
    private final Clock clock;
    private final LongSupplier nanoTime;
    private final Duration maxRequestAge;
    private final ExecutorService executor;
    private volatile CachedToken cached;
    private Request inFlight;

    public OcspTokenProvider(IdpTokenService tokenService, Clock clock) {
        this(tokenService, clock, System::nanoTime, MAX_REQUEST_AGE);
    }

    OcspTokenProvider(IdpTokenService tokenService, Clock clock, LongSupplier nanoTime, Duration maxRequestAge) {
        this.tokenService = Objects.requireNonNull(tokenService, "tokenService");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.nanoTime = Objects.requireNonNull(nanoTime, "nanoTime");
        this.maxRequestAge = Objects.requireNonNull(maxRequestAge, "maxRequestAge");
        // a cached pool: a request thread that ignores interruption does not hold up the next request
        this.executor = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "ocsp-token");
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * @param timeout how long the caller can wait for a new token
     * @return a bearer token
     * @throws OcspResponderException of type {@code TOKEN} when no token is available in time
     */
    public String token(Duration timeout) {
        CachedToken current = cached;
        if (current != null && clock.instant().plus(EXPIRY_MARGIN).isBefore(current.expiresAt())) {
            return current.value();
        }
        Future<String> request = request();
        try {
            String token = request.get(Math.max(timeout.toMillis(), 1), TimeUnit.MILLISECONDS);
            cached = new CachedToken(token, expiry(token));
            return token;
        } catch (TimeoutException e) {
            throw new OcspResponderException.Retryable(
                    OcspResponderException.Type.TOKEN, "Timed out waiting for an IdP token for the OCSP request", e);
        } catch (CancellationException e) {
            throw new OcspResponderException.Retryable(
                    OcspResponderException.Type.TOKEN, "IdP token request was abandoned after hanging", e);
        } catch (ExecutionException e) {
            throw new OcspResponderException.Retryable(
                    OcspResponderException.Type.TOKEN,
                    "Could not obtain an IdP token for the OCSP request",
                    e.getCause());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OcspResponderException(
                    OcspResponderException.Type.TOKEN, "Interrupted waiting for an IdP token", e);
        }
    }

    private synchronized Future<String> request() {
        long now = nanoTime.getAsLong();
        if (inFlight != null
                && !inFlight.future().isDone()
                && now - inFlight.startedNanos() > maxRequestAge.toNanos()) {
            log.warn(
                    "IdP token request for OCSP has not finished after {} s; abandoning it and starting a new one",
                    maxRequestAge.toSeconds());
            inFlight.future().cancel(true);
            inFlight = null;
        }
        if (inFlight == null || inFlight.future().isDone()) {
            inFlight = new Request(executor.submit(() -> tokenService.fetchToken((String) null)), now);
        }
        return inFlight.future();
    }

    private Instant expiry(String token) {
        try {
            Date expiration = SignedJWT.parse(token).getJWTClaimsSet().getExpirationTime();
            if (expiration != null) {
                return expiration.toInstant();
            }
        } catch (ParseException e) {
            // not a JWT we can read; fall through to the default lifetime
        }
        return clock.instant().plus(UNKNOWN_EXPIRY);
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }
}
