/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

/**
 * Finds the CA certificate that issued a peer's leaf certificate: the next certificate of the presented chain, or a
 * trusted CA from the truststore when the peer sent only its leaf. Both are only used after the chain has been
 * validated against the truststore.
 */
public final class IssuerResolver {

    private IssuerResolver() {}

    /**
     * @param chain          the chain presented by the peer, leaf first
     * @param trustedIssuers the CA certificates of the truststore
     * @return the issuer of {@code chain[0]}, if found
     */
    public static Optional<X509Certificate> issuerOf(X509Certificate[] chain, List<X509Certificate> trustedIssuers) {
        if (chain == null || chain.length == 0) {
            return Optional.empty();
        }
        X509Certificate leaf = chain[0];
        if (chain.length > 1 && isIssuer(chain[1], leaf)) {
            return Optional.of(chain[1]);
        }
        return trustedIssuers.stream().filter(ca -> isIssuer(ca, leaf)).findFirst();
    }

    private static boolean isIssuer(X509Certificate candidate, X509Certificate leaf) {
        if (!candidate.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) {
            return false;
        }
        try {
            leaf.verify(candidate.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}
