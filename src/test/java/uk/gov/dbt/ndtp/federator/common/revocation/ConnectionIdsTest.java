/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.Test;

class ConnectionIdsTest {

    private static SSLSession session(byte[] id) {
        SSLSession session = mock(SSLSession.class);
        when(session.getId()).thenReturn(id);
        return session;
    }

    @Test
    void addressAndFirstEightBytesOfTheSessionId() {
        byte[] id = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        assertEquals("/10.0.0.5:51234/0102030405060708", ConnectionIds.of("/10.0.0.5:51234", session(id)));
    }

    @Test
    void unknownAddressKeepsTheSessionPart() {
        assertEquals("-/0a0b", ConnectionIds.of(null, session(new byte[] {10, 11})));
    }

    @Test
    void noSessionGivesTheAddressOnly() {
        assertEquals("/10.0.0.5:1", ConnectionIds.of("/10.0.0.5:1", null));
        assertEquals("-", ConnectionIds.of(null, session(new byte[0])));
    }
}
