/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.util.Locale;
import lombok.Getter;

/**
 * The OCSP responder gave no usable answer: it could not be reached, refused the request, answered with an OCSP
 * error status, or its response failed verification. Never cached; treated as "status not available".
 * <p>
 * This base class is not retried. {@link Retryable} marks failures that a further attempt may resolve.
 */
@Getter
public class OcspResponderException extends RuntimeException {

    /** Kind of failure, used as the {@code type}/{@code cause} tag in logs and metrics. */
    public enum Type {
        UNREACHABLE,
        TIMEOUT,
        UNAUTHORIZED,
        HTTP_ERROR,
        TRY_LATER,
        INTERNAL_ERROR,
        MALFORMED_REQUEST,
        INVALID_RESPONSE,
        CIRCUIT_OPEN,
        TOKEN;

        public String tag() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    private final Type type;

    public OcspResponderException(Type type, String message) {
        super(message);
        this.type = type;
    }

    public OcspResponderException(Type type, String message, Throwable cause) {
        super(message, cause);
        this.type = type;
    }

    /** A failure that another attempt may resolve (network error, timeout, {@code tryLater}, HTTP 5xx). */
    public static class Retryable extends OcspResponderException {

        public Retryable(Type type, String message) {
            super(type, message);
        }

        public Retryable(Type type, String message, Throwable cause) {
            super(type, message, cause);
        }
    }
}
