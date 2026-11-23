/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation.support;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Properties;
import org.slf4j.LoggerFactory;
import uk.gov.dbt.ndtp.federator.common.revocation.RevocationProperties;
import uk.gov.dbt.ndtp.federator.common.service.idp.IdpTokenService;
import uk.gov.dbt.ndtp.federator.common.utils.PropertyUtil;

/** Shared helpers for revocation tests. */
public final class RevocationTestSupport {

    public static final String SIGNER_CN = "ocsp-signer.management-node";

    private RevocationTestSupport() {}

    /** Replaces the PropertyUtil configuration with the given properties. */
    public static void initProperties(Path dir, Map<String, String> values) {
        Properties properties = new Properties();
        properties.putAll(values);
        try {
            Path file = Files.createTempFile(dir, "test", ".properties");
            try (var out = Files.newOutputStream(file)) {
                properties.store(out, null);
            }
            PropertyUtil.clear();
            PropertyUtil.init(file.toFile());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Settings for tests: 1 s per attempt, 2 attempts, nonce and signer EKU required, memory cache. */
    public static RevocationProperties properties(URI ocspUri, Duration ttl) {
        return new RevocationProperties(
                true,
                ocspUri,
                Duration.ofSeconds(1),
                2,
                true,
                true,
                SIGNER_CN,
                RevocationProperties.CacheType.MEMORY,
                ttl,
                1000);
    }

    public static IdpTokenService tokenService() {
        IdpTokenService service = mock(IdpTokenService.class);
        when(service.fetchToken(any())).thenReturn("test-token");
        return service;
    }

    /** Captures the events of a logback logger. Detach with {@link #detach(String, ListAppender)}. */
    public static ListAppender<ILoggingEvent> captureLogs(String loggerName) {
        Logger logger = (Logger) LoggerFactory.getLogger(loggerName);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        return appender;
    }

    public static void detach(String loggerName, ListAppender<ILoggingEvent> appender) {
        ((Logger) LoggerFactory.getLogger(loggerName)).detachAppender(appender);
    }

    /** A clock that tests move forward by hand. */
    public static final class MutableClock extends Clock {
        private volatile Instant now;

        public MutableClock(Instant start) {
            this.now = start;
        }

        public void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
