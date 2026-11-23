/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.grpc.Status;
import org.junit.jupiter.api.Test;

class RevocationVerdictTest {

    private static RevocationDecision status(CertificateStatus status) {
        return new RevocationDecision.Status(new CertificateStatusEntry(status, 0, null, 0), true);
    }

    private static final RevocationDecision FAILURE = new RevocationDecision.ResponderFailure(
            new OcspResponderException(OcspResponderException.Type.TIMEOUT, "slow"));

    @Test
    void goodIsAllowed() {
        RevocationVerdict verdict = RevocationVerdict.of(status(CertificateStatus.GOOD), true);
        assertTrue(verdict.allowed());
        assertEquals("good", verdict.status());
        assertEquals("none", verdict.cause());
    }

    @Test
    void revokedAndUnknownAreRejectedWithUnauthenticatedEvenWhenFailingOpen() {
        for (CertificateStatus status :
                new CertificateStatus[] {CertificateStatus.REVOKED, CertificateStatus.UNKNOWN}) {
            RevocationVerdict verdict = RevocationVerdict.of(status(status), false);
            assertFalse(verdict.allowed());
            assertEquals(Status.Code.UNAUTHENTICATED, verdict.rejection().getCode());
            assertEquals(verdict.status(), verdict.cause());
        }
    }

    @Test
    void unavailableDependsOnFailClosed() {
        RevocationVerdict closed = RevocationVerdict.of(FAILURE, true);
        assertFalse(closed.allowed());
        assertTrue(closed.unavailable());
        assertEquals(Status.Code.UNAVAILABLE, closed.rejection().getCode());

        RevocationVerdict open = RevocationVerdict.of(FAILURE, false);
        assertTrue(open.allowed());
        assertEquals("unavailable", open.cause());
    }
}
