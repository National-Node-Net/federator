/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import javax.net.ssl.SSLSession;
import org.bouncycastle.util.encoders.Hex;

/**
 * Identifier of one TLS connection in revocation logs: {@code <remote address>/<first 8 bytes of the TLS session id>}.
 * The session part is the same in the handshake log and in the logs of the calls on that connection, so they can be
 * correlated even where the remote address is not known (the TLS handshake on the gRPC server).
 */
public final class ConnectionIds {

    private static final int SESSION_ID_BYTES = 8;

    private ConnectionIds() {}

    /**
     * @param address remote address, or null when unknown
     * @param session TLS session (or handshake session), or null
     * @return the connection id, {@code -} parts for unknown values
     */
    public static String of(String address, SSLSession session) {
        String host = address == null || address.isBlank() ? "-" : address;
        byte[] id = session == null ? null : session.getId();
        if (id == null || id.length == 0) {
            return host;
        }
        return host + "/" + Hex.toHexString(id, 0, Math.min(id.length, SESSION_ID_BYTES));
    }
}
