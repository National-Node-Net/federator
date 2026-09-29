package uk.gov.dbt.ndtp.federator.common.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.net.ConnectException;
import java.util.List;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import uk.gov.dbt.ndtp.federator.exceptions.FederatorTokenException;

/**
 * Verifies that every failed attempt is logged at WARN with the underlying cause and stack trace.
 */
class ResilienceSupportLoggingTest {

    private static final String COMPONENT_NAME = "idp-logging-test";

    private ListAppender<ILoggingEvent> appender;
    private Logger logger;

    @BeforeEach
    void setup() {
        ResilienceSupport.clearForTests();
        PropertyUtil.clear();
        PropertyUtil.init("test.properties");
        PropertyUtil propertyUtil = PropertyUtil.getInstance();
        propertyUtil.properties.setProperty("management.node.resilience.retry.maxAttempts", "3");
        propertyUtil.properties.setProperty("management.node.resilience.retry.initialWait", "PT0.01S");
        propertyUtil.properties.setProperty("management.node.resilience.retry.retryOn", "java.lang.RuntimeException");

        logger = (Logger) LoggerFactory.getLogger(ResilienceSupport.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(appender);
        ResilienceSupport.clearForTests();
        PropertyUtil.clear();
    }

    @Test
    void shouldLogEachFailedAttemptAndFinalFailureAtWarnWithCauseAndStackTrace() {
        ConnectException rootCause = new ConnectException();
        FederatorTokenException failure =
                new FederatorTokenException("Error fetching token from IDP at https://idp/token", rootCause);
        Supplier<String> supplier = () -> {
            throw failure;
        };

        assertThrows(
                FederatorTokenException.class,
                () -> ResilienceSupport.decorateAndExecute(COMPONENT_NAME, "fetch token", null, supplier));

        List<ILoggingEvent> warnings =
                appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
        assertEquals(3, warnings.size(), "expected 2 retry warnings and 1 final warning");

        for (ILoggingEvent warning : warnings) {
            String message = warning.getFormattedMessage();
            assertTrue(message.contains(COMPONENT_NAME), message);
            assertTrue(message.contains("https://idp/token"), message);
            assertTrue(message.contains("ConnectException"), message);
            assertNotNull(warning.getThrowableProxy(), "stack trace must be attached");
        }
        assertTrue(warnings.get(0).getFormattedMessage().contains("attempt 1 of 3 failed"));
        assertTrue(warnings.get(2).getFormattedMessage().contains("giving up after 3 attempt(s)"));
    }

    @Test
    void shouldLogNonRetryableFailureAtWarn() {
        PropertyUtil.getInstance()
                .properties
                .setProperty("management.node.resilience.retry.retryOn", "java.io.IOException");
        ResilienceSupport.clearForTests();
        Supplier<String> supplier = () -> {
            throw new IllegalStateException("boom");
        };

        assertThrows(
                IllegalStateException.class,
                () -> ResilienceSupport.decorateAndExecute(COMPONENT_NAME, "fetch token", null, supplier));

        List<ILoggingEvent> warnings =
                appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).getFormattedMessage().contains("not retryable"));
        assertTrue(warnings.get(0).getFormattedMessage().contains("IllegalStateException: boom"));
        assertNotNull(warnings.get(0).getThrowableProxy());
    }

    @Test
    void describeCauseShouldIncludeWholeChainAndClassNamesForNullMessages() {
        Throwable ex = new FederatorTokenException("outer", new RuntimeException(new ConnectException()));

        assertEquals(
                "FederatorTokenException: outer -> RuntimeException: java.net.ConnectException -> ConnectException",
                ResilienceSupport.describeCause(ex));
        assertEquals("unknown", ResilienceSupport.describeCause(null));
    }
}
