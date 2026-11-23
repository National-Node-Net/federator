/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

/**
 * Certificate status reported by the OCSP responder (RFC 6960 {@code CertStatus}).
 */
public enum CertificateStatus {
    GOOD,
    REVOKED,
    UNKNOWN
}
