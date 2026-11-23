/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import uk.gov.dbt.ndtp.federator.common.service.idp.IdpTokenService;

class OcspTokenProviderTest {

    @Test
    void tokenIsReusedUntilItExpires() {
        IdpTokenService service = mock(IdpTokenService.class);
        when(service.fetchToken(any())).thenReturn("opaque-token");
        try (OcspTokenProvider provider = new OcspTokenProvider(service, Clock.systemUTC())) {
            assertEquals("opaque-token", provider.token(Duration.ofSeconds(2)));
            assertEquals("opaque-token", provider.token(Duration.ofSeconds(2)));
        }
        verify(service, times(1)).fetchToken(any());
    }

    @Test
    void hangingRequestIsAbandonedAndReplaced() throws Exception {
        IdpTokenService service = mock(IdpTokenService.class);
        CountDownLatch never = new CountDownLatch(1);
        when(service.fetchToken(any()))
                .thenAnswer(invocation -> {
                    never.await(); // an IdP that accepts the connection and never answers
                    return "late";
                })
                .thenReturn("fresh-token");
        AtomicLong now = new AtomicLong();
        try (OcspTokenProvider provider =
                new OcspTokenProvider(service, Clock.systemUTC(), now::get, Duration.ofSeconds(35))) {

            OcspResponderException first =
                    assertThrows(OcspResponderException.class, () -> provider.token(Duration.ofMillis(100)));
            assertEquals(OcspResponderException.Type.TOKEN, first.getType());

            // still within the maximum age: the same hanging request is awaited again
            now.addAndGet(Duration.ofSeconds(10).toNanos());
            assertThrows(OcspResponderException.class, () -> provider.token(Duration.ofMillis(50)));
            verify(service, times(1)).fetchToken(any());

            // past the maximum age: abandoned, a new request is made
            now.addAndGet(Duration.ofSeconds(30).toNanos());
            assertEquals("fresh-token", provider.token(Duration.ofSeconds(2)));
            verify(service, times(2)).fetchToken(any());
        }
    }
}
