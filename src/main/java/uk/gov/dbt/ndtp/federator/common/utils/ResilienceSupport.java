/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.utils;

import static java.lang.Math.min;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.core.IntervalFunction;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.exceptions.JedisException;
import uk.gov.dbt.ndtp.federator.exceptions.RebuildableRuntimeException;

/**
 * Centralized Resilience4j configuration and decoration helpers.
 * <p>
 * The static methods use the policy configured under {@code management.node.resilience.*}.
 * Callers that need their own settings (for example OCSP revocation checks under
 * {@code revocation.ocsp.resilience.*}) create a separate {@link Policy}.
 */
public final class ResilienceSupport {

    private static final Logger LOG = LoggerFactory.getLogger(ResilienceSupport.class);

    /** Property prefix of the policy used for Management Node and IdP calls. */
    public static final String MANAGEMENT_NODE_PREFIX = "management.node.resilience";

    private static final AtomicReference<Policy> defaultPolicy = new AtomicReference<>();

    private ResilienceSupport() {}

    private static Policy getDefaultPolicy() {
        return defaultPolicy.updateAndGet(
                current -> current != null ? current : new Policy(MANAGEMENT_NODE_PREFIX, Defaults.MANAGEMENT_NODE));
    }

    /**
     * Builds a one-line description of the whole cause chain, e.g.
     * {@code FederatorTokenException: Error fetching token -> ConnectException: Connection refused}.
     * Many JDK network exceptions have a null message, so the class name is always included.
     */
    static String describeCause(Throwable ex) {
        if (ex == null) {
            return "unknown";
        }
        StringBuilder sb = new StringBuilder();
        java.util.Set<Throwable> seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        Throwable current = ex;
        while (current != null && seen.add(current)) {
            if (!sb.isEmpty()) {
                sb.append(" -> ");
            }
            sb.append(current.getClass().getSimpleName());
            if (current.getMessage() != null && !current.getMessage().isBlank()) {
                sb.append(": ").append(current.getMessage());
            }
            current = current.getCause();
        }
        return sb.toString();
    }

    public static Retry getRetry(String name) {
        return getDefaultPolicy().getRetry(name);
    }

    public static CircuitBreaker getCircuitBreaker(String name) {
        return getDefaultPolicy().getCircuitBreaker(name);
    }

    /**
     * Testing helper to clear registries so tests can reconfigure policies per
     * test.
     */
    public static void clearForTests() {
        defaultPolicy.set(null);
    }

    public static <T> T decorateAndExecute(
            String componentName, String operation, String targetId, Supplier<T> supplier) {
        return getDefaultPolicy().decorateAndExecute(componentName, operation, targetId, supplier);
    }

    /**
     * Defaults used when a property under the policy prefix is not set.
     *
     * @param maxAttempts          attempts in total, including the first call
     * @param initialWait          wait before the first retry, doubled before each further retry
     * @param maxBackoff           cap on the wait between retries
     * @param retryOn              comma-separated Throwable classes that are retried
     * @param failureRateThreshold failure percentage that opens the circuit breaker
     * @param slidingWindowSize    number of calls used to compute the failure rate
     * @param minimumNumberOfCalls calls needed before the failure rate is evaluated
     * @param permittedHalfOpen    test calls allowed while half-open
     * @param waitInOpenState      time the breaker stays open
     */
    public record Defaults(
            int maxAttempts,
            Duration initialWait,
            Duration maxBackoff,
            String retryOn,
            float failureRateThreshold,
            int slidingWindowSize,
            int minimumNumberOfCalls,
            int permittedHalfOpen,
            Duration waitInOpenState) {

        /** Defaults of the {@code management.node.resilience} policy. */
        public static final Defaults MANAGEMENT_NODE = new Defaults(
                10,
                Duration.ofMillis(5000),
                Duration.ofMinutes(15),
                "java.lang.RuntimeException",
                50.0f,
                10,
                20,
                1,
                Duration.ofSeconds(60));
    }

    /**
     * A retry and circuit breaker configuration read from properties under one prefix, with its own registries.
     * Every retry and circuit breaker obtained from a policy logs its retries and state transitions.
     */
    public static final class Policy {

        private final String prefix;
        private final RetryRegistry retryRegistry;
        private final CircuitBreakerRegistry circuitBreakerRegistry;

        /**
         * Reads the policy from {@code <prefix>.retry.*} and {@code <prefix>.circuitBreaker.*}.
         *
         * @param prefix   property prefix without a trailing dot, e.g. {@code revocation.ocsp.resilience}
         * @param defaults values used for properties that are not set
         */
        public Policy(String prefix, Defaults defaults) {
            this.prefix = Objects.requireNonNull(prefix, "prefix");
            Objects.requireNonNull(defaults, "defaults");
            this.retryRegistry = RetryRegistry.of(buildRetryConfig(defaults));
            this.retryRegistry
                    .getEventPublisher()
                    .onEntryAdded(event -> registerRetryEventLogging(event.getAddedEntry()));
            this.circuitBreakerRegistry = CircuitBreakerRegistry.of(buildCircuitBreakerConfig(defaults));
            this.circuitBreakerRegistry
                    .getEventPublisher()
                    .onEntryAdded(event -> registerCircuitBreakerEventLogging(event.getAddedEntry()));
        }

        public Retry getRetry(String name) {
            Objects.requireNonNull(name);
            return retryRegistry.retry(name);
        }

        public CircuitBreaker getCircuitBreaker(String name) {
            Objects.requireNonNull(name);
            return circuitBreakerRegistry.circuitBreaker(name);
        }

        /** The circuit breaker registry, e.g. for binding metrics. */
        public CircuitBreakerRegistry circuitBreakerRegistry() {
            return circuitBreakerRegistry;
        }

        /**
         * Runs the supplier through the circuit breaker and retry named {@code componentName}.
         * A {@link RebuildableRuntimeException} is rethrown with an enriched message; other exceptions as they are.
         */
        public <T> T decorateAndExecute(String componentName, String operation, String targetId, Supplier<T> supplier) {
            Retry retry = getRetry(componentName);
            CircuitBreaker circuitBreaker = getCircuitBreaker(componentName);

            Supplier<T> withCb = CircuitBreaker.decorateSupplier(circuitBreaker, supplier);
            Supplier<T> withRetry = Retry.decorateSupplier(retry, withCb);

            try {
                return withRetry.get();
            } catch (RuntimeException ex) {
                enrichAndRethrow(ex, componentName, operation, targetId);
                return null;
            }
        }

        /**
         * Logs every failed attempt at WARN with the underlying cause and full stack trace,
         * so connectivity problems (DNS, refused connection, TLS, HTTP status) are visible while retrying.
         */
        private void registerRetryEventLogging(Retry retry) {
            final String name = retry.getName();
            final int maxAttempts = retry.getRetryConfig().getMaxAttempts();
            final String retryOnProperty = prefix + ".retry.retryOn";
            retry.getEventPublisher()
                    .onRetry(event -> LOG.warn(
                            "Resilience retry [{}]: attempt {} of {} failed, retrying in {} ms. Cause: {}",
                            name,
                            event.getNumberOfRetryAttempts(),
                            maxAttempts,
                            event.getWaitInterval().toMillis(),
                            describeCause(event.getLastThrowable()),
                            event.getLastThrowable()))
                    .onError(event -> LOG.warn(
                            "Resilience retry [{}]: giving up after {} attempt(s). Cause: {}",
                            name,
                            event.getNumberOfRetryAttempts(),
                            describeCause(event.getLastThrowable()),
                            event.getLastThrowable()))
                    .onIgnoredError(event -> LOG.warn(
                            "Resilience retry [{}]: failure is not retryable (see {}), not retrying. Cause: {}",
                            name,
                            retryOnProperty,
                            describeCause(event.getLastThrowable()),
                            event.getLastThrowable()));
        }

        private static void registerCircuitBreakerEventLogging(CircuitBreaker circuitBreaker) {
            final String name = circuitBreaker.getName();
            circuitBreaker
                    .getEventPublisher()
                    .onStateTransition(event -> LOG.warn(
                            "Resilience circuit breaker [{}]: state changed {} (failure rate {}%)",
                            name,
                            event.getStateTransition(),
                            circuitBreaker.getMetrics().getFailureRate()));
        }

        private RetryConfig buildRetryConfig(Defaults defaults) {
            int maxAttempts = PropertyUtil.getPropertyIntValue(
                    prefix + ".retry.maxAttempts", String.valueOf(defaults.maxAttempts()));
            Duration maxBackoff = PropertyUtil.getPropertyDurationValue(
                    prefix + ".retry.maxBackoff", defaults.maxBackoff().toString());
            Duration initialWait = PropertyUtil.getPropertyDurationValue(
                    prefix + ".retry.initialWait", defaults.initialWait().toString());
            String retryOnClasses = PropertyUtil.getPropertyValue(prefix + ".retry.retryOn", defaults.retryOn());

            IntervalFunction intervalFn = getIntervalFunction(initialWait, maxBackoff);

            RetryConfig.Builder<Object> builder =
                    RetryConfig.custom().maxAttempts(maxAttempts).intervalFunction(intervalFn);

            // Configure which exception classes are retryable
            Class<?>[] retryables = parseExceptionClasses(retryOnClasses);
            if (retryables.length > 0) {
                // Safe cast: Resilience4j expects Class<? extends Throwable>[]
                @SuppressWarnings("unchecked")
                Class<? extends Throwable>[] throwableClasses = (Class<? extends Throwable>[]) retryables;
                builder.retryExceptions(throwableClasses);
            } else {
                builder.retryExceptions(RuntimeException.class);
            }

            return builder.build();
        }

        private CircuitBreakerConfig buildCircuitBreakerConfig(Defaults defaults) {
            String cb = prefix + ".circuitBreaker.";
            float failureRateThreshold = parseFloat(cb + "failureRateThreshold", defaults.failureRateThreshold());
            int slidingWindowSize = PropertyUtil.getPropertyIntValue(
                    cb + "slidingWindowSize", String.valueOf(defaults.slidingWindowSize()));
            int minimumNumberOfCalls = PropertyUtil.getPropertyIntValue(
                    cb + "minimumNumberOfCalls", String.valueOf(defaults.minimumNumberOfCalls()));
            int permittedHalfOpen = PropertyUtil.getPropertyIntValue(
                    cb + "permittedNumberOfCallsInHalfOpenState", String.valueOf(defaults.permittedHalfOpen()));
            Duration waitOpen = PropertyUtil.getPropertyDurationValue(
                    cb + "waitDurationInOpenState", defaults.waitInOpenState().toString());

            return CircuitBreakerConfig.custom()
                    .failureRateThreshold(failureRateThreshold)
                    .slidingWindowSize(slidingWindowSize)
                    .minimumNumberOfCalls(minimumNumberOfCalls)
                    .permittedNumberOfCallsInHalfOpenState(permittedHalfOpen)
                    .waitDurationInOpenState(waitOpen)
                    .build();
        }
    }

    private static @NonNull IntervalFunction getIntervalFunction(Duration initialWait, Duration maxBackoff) {
        return attempt -> {
            // attempt starts at 1 for first retry
            long base = initialWait.toMillis();
            long max = maxBackoff.toMillis();
            long factor = 1L << Math.clamp(attempt - 1L, 0L, 30L);
            long next = min(base * factor, max);
            LOG.debug("Resilience retry: attempt {} will wait {} ms before next try (cap {} ms)", attempt, next, max);
            return next;
        };
    }

    private static float parseFloat(String key, float def) {
        String v = PropertyUtil.getPropertyValue(key, String.valueOf(def));
        try {
            return Float.parseFloat(v.trim());
        } catch (Exception e) {
            return def;
        }
    }

    private static Class<?>[] parseExceptionClasses(String csv) {
        if (csv == null || csv.trim().isEmpty()) return new Class<?>[0];
        String[] parts = csv.split(",");
        java.util.List<Class<?>> classes = new java.util.ArrayList<>();
        for (String p : parts) {
            String name = p.trim();
            if (name.isEmpty()) continue;
            try {
                Class<?> cls = Class.forName(name);
                if (Throwable.class.isAssignableFrom(cls)) {
                    classes.add(cls);
                } else {
                    LOG.warn("Configured retry class {} is not a Throwable and will be ignored", name);
                }
            } catch (ClassNotFoundException e) {
                LOG.warn("Configured retry class {} not found; ignoring", name);
            }
        }
        return classes.toArray(new Class<?>[0]);
    }

    /**
     * A helper method that builds a detailed error message
     *
     * @param baseMessage   the base message for the exception
     * @param ex            the exception thrown
     * @param componentName the name of the component throwing the exception
     * @param operation     the name of the operation throwing the exception
     * @param targetId      the target id for the operation
     * @return an enriched failure message
     */
    public static String buildFailureMessage(
            String baseMessage, Throwable ex, String componentName, String operation, String targetId) {
        return buildFailureMessage(baseMessage, getExceptionDetails(ex, componentName, operation), targetId);
    }

    /**
     * A helper method that builds a detailed error message
     *
     * @param ex            the exception thrown
     * @param componentName the name of the component throwing the exception
     * @param operation     the name of the operation throwing the exception
     * @param targetId      the target id for the operation
     * @return an enriched failure message
     */
    private static String buildFailureMessage(Throwable ex, String componentName, String operation, String targetId) {
        return buildFailureMessage(ex.getMessage(), getExceptionDetails(ex, componentName, operation), targetId);
    }

    /**
     * A helper method to fetch human readabe details from parameters
     *
     * @param ex            the exception throw
     * @param componentName the name of the component throwing the exception
     * @param operation     the name of the operation where the exception is thrown
     * @return a string with human readable details from the provided parameters
     */
    private static String getExceptionDetails(Throwable ex, String componentName, String operation) {
        Throwable root = getRootCause(ex);

        return switch (root) {
            case java.net.SocketTimeoutException ignored -> "timeout while calling " + componentName;

            case java.net.http.HttpTimeoutException ignored -> "timeout while calling " + componentName;

            case java.io.InterruptedIOException ignored -> {
                Thread.currentThread().interrupt();
                yield "request was interrupted";
            }

            case InterruptedException ignored -> {
                Thread.currentThread().interrupt();
                yield "request was interrupted";
            }

            case java.io.IOException ignored -> "I/O error while calling " + componentName;

            case JedisException ignored -> "redis cache failure";

            default -> "unexpected failure during " + operation;
        };
    }

    /**
     * A helper method that creates a detailed formatted error message
     *
     * @param baseMessage the base message included in the original exception
     * @param detail      the human readable detailed message for the exception
     * @param targetId    the target id for the operation
     * @return a detailed formatted error message
     */
    private static String buildFailureMessage(String baseMessage, String detail, String targetId) {

        String targetSuffix = (targetId != null && !targetId.isBlank()) ? " for " + targetId : "";

        return "%s (%s%s)".formatted((baseMessage == null ? "" : baseMessage), detail, targetSuffix);
    }

    private static Throwable getRootCause(Throwable ex) {
        Throwable current = ex;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    /**
     * Enriches the message of a RebuildableRuntimeException and rethrows it.
     * If the exception is not a RebuildableRuntimeException it is rethrown as-is.
     *
     * @param e the exception to enrich
     * @param componentName the name of the component involved in the exception
     * @param operation the name of the operation attempted before the exception was raised
     * @param targetId the id of the target involved in the exception
     */
    private static void enrichAndRethrow(RuntimeException ex, String componentName, String operation, String targetId) {
        if (!(ex instanceof RebuildableRuntimeException rebuildableRuntimeException)) {
            throw ex;
        }

        String enrichedMessage = buildFailureMessage(ex, componentName, operation, targetId);
        throw rebuildableRuntimeException.rebuild(enrichedMessage, ex);
    }
}
