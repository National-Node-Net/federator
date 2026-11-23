/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.revocation;

import static uk.gov.dbt.ndtp.federator.common.revocation.OcspResponderException.Type.INVALID_RESPONSE;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * Verifies a successful OCSP response (RFC 6960) before its status is used.
 * <p>
 * The response must be signed either by the CA that issued the checked certificate or by a delegated responder
 * certificate issued by that CA, currently valid, with the {@code id-kp-OCSPSigning} EKU and, if key usage is present,
 * {@code digitalSignature}. The signer's own revocation status is not checked (short signer lifetime instead).
 * <p>
 * Transitional: with {@code requireSignerEku=false}, a delegated signer without the EKU is accepted when its common
 * name equals {@code signerCommonName}. The Management Node issues its signer through the default PKI role until the
 * dedicated OCSP signer role is in place; remove this once it is.
 * <p>
 * It also checks the nonce, that a single response answers the requested certificate ID, and the
 * {@code thisUpdate}/{@code nextUpdate} window with a clock skew of {@link #CLOCK_SKEW}.
 * Every violation is an {@link OcspResponderException} of type {@code INVALID_RESPONSE}.
 * Signatures are verified with the JDK's JCA providers, not the Bouncy Castle provider.
 */
@Slf4j
public class OcspResponseVerifier {

    public static final Duration CLOCK_SKEW = Duration.ofSeconds(30);

    private static final String OCSP_SIGNING = KeyPurposeId.id_kp_OCSPSigning.getId();
    private static final int DIGITAL_SIGNATURE = 0;

    private final boolean requireNonce;
    private final boolean requireSignerEku;
    private final String signerCommonName;
    private final Clock clock;
    private final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
    private final AtomicReference<BigInteger> lastLaxSigner = new AtomicReference<>();
    /** Thread-safe factory; a {@link DigestCalculator} itself is stateful and must not be shared between threads. */
    private final DigestCalculatorProvider digests;

    public OcspResponseVerifier(boolean requireNonce, boolean requireSignerEku, String signerCommonName, Clock clock) {
        this.requireNonce = requireNonce;
        this.requireSignerEku = requireSignerEku;
        this.signerCommonName = signerCommonName;
        this.clock = Objects.requireNonNull(clock, "clock");
        try {
            this.digests = new JcaDigestCalculatorProviderBuilder().build();
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Digest calculator provider not available", e);
        }
    }

    /**
     * Verifies the response and returns the status of the requested certificate.
     *
     * @param response     the OCSP response; its status must be {@code successful}
     * @param requested    the certificate ID that was asked for
     * @param requestNonce the nonce extension sent in the request, or null when none was sent
     * @param issuer       the CA certificate that issued the checked certificate
     * @return the verified status entry, with {@code cachedAt} = now
     * @throws OcspResponderException when the response must not be trusted
     */
    public CertificateStatusEntry verify(
            OCSPResp response, CertificateID requested, Extension requestNonce, X509Certificate issuer) {
        if (response.getStatus() != OCSPResp.SUCCESSFUL) {
            throw invalid("OCSP response status is " + response.getStatus() + ", not successful");
        }
        BasicOCSPResp basic = basicResponse(response);
        Instant now = clock.instant();

        X509Certificate signer = findSigner(basic, issuer);
        verifySigner(signer, issuer, now);
        verifySignature(basic, signer);
        verifyNonce(basic, requestNonce);
        SingleResp single = findSingleResponse(basic, requested);
        return toEntry(single, now);
    }

    private static BasicOCSPResp basicResponse(OCSPResp response) {
        try {
            Object object = response.getResponseObject();
            if (object instanceof BasicOCSPResp basic) {
                return basic;
            }
            throw invalid("OCSP response does not contain a basic response");
        } catch (OCSPException e) {
            throw new OcspResponderException(INVALID_RESPONSE, "OCSP response cannot be parsed", e);
        }
    }

    /** The CA itself or the delegated certificate in {@code certs} that matches the responder ID. */
    private X509Certificate findSigner(BasicOCSPResp basic, X509Certificate issuer) {
        RespID responderId = basic.getResponderId();
        try {
            X509CertificateHolder issuerHolder = new X509CertificateHolder(issuer.getEncoded());
            if (matches(responderId, issuerHolder)) {
                return issuer;
            }
            for (X509CertificateHolder candidate : basic.getCerts()) {
                if (matches(responderId, candidate)) {
                    return converter.getCertificate(candidate);
                }
            }
        } catch (CertificateException | java.io.IOException e) {
            throw new OcspResponderException(INVALID_RESPONSE, "OCSP signer certificate cannot be read", e);
        }
        throw invalid("No certificate in the OCSP response matches its responder ID");
    }

    private boolean matches(RespID responderId, X509CertificateHolder certificate) {
        try {
            DigestCalculator sha1 = digests.get(CertificateID.HASH_SHA1);
            return responderId.equals(new RespID(certificate.getSubjectPublicKeyInfo(), sha1))
                    || responderId.equals(new RespID(certificate.getSubject()));
        } catch (OCSPException | OperatorCreationException e) {
            return false;
        }
    }

    private void verifySigner(X509Certificate signer, X509Certificate issuer, Instant now) {
        if (signer == issuer) {
            return; // the CA signs its own responses; it is trusted through the validated certificate chain
        }
        try {
            signer.verify(issuer.getPublicKey());
        } catch (GeneralSecurityException e) {
            throw new OcspResponderException(
                    INVALID_RESPONSE, "OCSP signer is not issued by the CA of the checked certificate", e);
        }
        try {
            signer.checkValidity(Date.from(now));
        } catch (CertificateException e) {
            throw new OcspResponderException(INVALID_RESPONSE, "OCSP signer certificate is not valid now", e);
        }
        boolean[] keyUsage = signer.getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= DIGITAL_SIGNATURE || !keyUsage[DIGITAL_SIGNATURE])) {
            throw invalid("OCSP signer certificate does not allow digitalSignature");
        }
        if (hasOcspSigningEku(signer)) {
            return;
        }
        if (!requireSignerEku && signerCommonName.equals(commonName(signer))) {
            BigInteger serial = signer.getSerialNumber();
            if (!serial.equals(lastLaxSigner.getAndSet(serial))) {
                log.warn(
                        "Accepting OCSP signer CN={} serial={} without id-kp-OCSPSigning because"
                                + " revocation.ocsp.requireSignerEku=false. This is transitional; enable it once the"
                                + " Management Node issues its signer through the dedicated OCSP signer role.",
                        signerCommonName,
                        CertificateKey.serialHex(serial));
            }
            return;
        }
        throw invalid("OCSP signer certificate "
                + signer.getSubjectX500Principal().getName() + " has no id-kp-OCSPSigning extended key usage");
    }

    private static boolean hasOcspSigningEku(X509Certificate signer) {
        try {
            List<String> eku = signer.getExtendedKeyUsage();
            return eku != null && eku.contains(OCSP_SIGNING);
        } catch (CertificateException e) {
            return false;
        }
    }

    private static String commonName(X509Certificate certificate) {
        X500Name subject =
                X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        RDN[] rdns = subject.getRDNs(BCStyle.CN);
        if (rdns.length == 0) {
            return null;
        }
        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }

    private static void verifySignature(BasicOCSPResp basic, X509Certificate signer) {
        boolean valid;
        try {
            valid = basic.isSignatureValid(new JcaContentVerifierProviderBuilder().build(signer.getPublicKey()));
        } catch (OCSPException | OperatorCreationException e) {
            throw new OcspResponderException(INVALID_RESPONSE, "OCSP response signature cannot be verified", e);
        }
        if (!valid) {
            throw invalid("OCSP response signature is invalid");
        }
    }

    private void verifyNonce(BasicOCSPResp basic, Extension requestNonce) {
        Extension responseNonce = basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (requestNonce == null) {
            return;
        }
        if (responseNonce == null) {
            if (requireNonce) {
                throw invalid("OCSP response does not echo the request nonce");
            }
            return;
        }
        if (!Arrays.equals(
                requestNonce.getExtnValue().getOctets(),
                responseNonce.getExtnValue().getOctets())) {
            throw invalid("OCSP response nonce does not match the request");
        }
    }

    private static SingleResp findSingleResponse(BasicOCSPResp basic, CertificateID requested) {
        for (SingleResp single : basic.getResponses()) {
            if (requested.equals(single.getCertID())) {
                return single;
            }
        }
        throw invalid("OCSP response does not answer the requested certificate ID");
    }

    private static CertificateStatusEntry toEntry(SingleResp single, Instant now) {
        Instant thisUpdate = single.getThisUpdate().toInstant();
        if (thisUpdate.isAfter(now.plus(CLOCK_SKEW))) {
            throw invalid("OCSP thisUpdate " + thisUpdate + " is in the future");
        }
        Long nextUpdate = null;
        if (single.getNextUpdate() != null) {
            Instant next = single.getNextUpdate().toInstant();
            if (next.isBefore(now.minus(CLOCK_SKEW))) {
                throw invalid("OCSP nextUpdate " + next + " is in the past");
            }
            nextUpdate = next.toEpochMilli();
        }
        return new CertificateStatusEntry(
                status(single.getCertStatus()), thisUpdate.toEpochMilli(), nextUpdate, now.toEpochMilli());
    }

    private static CertificateStatus status(org.bouncycastle.cert.ocsp.CertificateStatus status) {
        if (status == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
            return CertificateStatus.GOOD;
        }
        if (status instanceof RevokedStatus) {
            return CertificateStatus.REVOKED;
        }
        if (status instanceof UnknownStatus) {
            return CertificateStatus.UNKNOWN;
        }
        throw invalid("OCSP response carries an unsupported certificate status");
    }

    private static OcspResponderException invalid(String message) {
        return new OcspResponderException(INVALID_RESPONSE, message);
    }

    /** Converts a certificate for the OCSP API; exposed for {@link OcspClient}. */
    static X509CertificateHolder holder(X509Certificate certificate) {
        try {
            return new X509CertificateHolder(certificate.getEncoded());
        } catch (CertificateEncodingException | java.io.IOException e) {
            throw new IllegalArgumentException("Certificate cannot be encoded", e);
        }
    }
}
