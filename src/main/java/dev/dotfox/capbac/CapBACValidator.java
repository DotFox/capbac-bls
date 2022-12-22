package dev.dotfox.capbac;

import java.net.URI;
import java.util.List;
import java.util.Stack;

import dev.dotfox.bls.BLS;
import dev.dotfox.bls.BLSPublicKey;
import dev.dotfox.bls.BLSSignature;
import dev.dotfox.capbac.CapBAC.BadID;
import dev.dotfox.capbac.CapBAC.BadSign;
import dev.dotfox.capbac.CapBAC.Expired;
import dev.dotfox.capbac.CapBAC.Invalid;
import dev.dotfox.capbac.CapBAC.Malformed;

public class CapBACValidator {
    private final CapBACTrustChecker trustChecker;
    private final CapBACResolver resolver;

    public CapBACValidator(CapBACTrustChecker trustChecker, CapBACResolver resolver) {
        this.trustChecker = trustChecker;
        this.resolver = resolver;
    }

    public void validate(CapBACCertificate certificate, long now) throws Expired, Invalid, BadID, BadSign, Malformed {
        if (!trustChecker.check(certificate.getRootIssuer())) {
            throw new Invalid("Untrusted root issuer.");
        }

        List<BLSPublicKey> pks = new Stack<BLSPublicKey>();
        List<byte[]> messages = new Stack<byte[]>();
        BLSSignature signature = BLS.signatureFromBytes(certificate.getSignature());

        verifyChain(pks, messages, signature, certificate, now);
    }

    public void validate(CapBACInvocation invocation, long now) throws Invalid, Expired, BadID, BadSign, Malformed {
        CapBACCertificate certificate = invocation.getCertificate();

        if (!trustChecker.check(certificate.getRootIssuer())) {
            throw new Invalid("Untrusted root issuer.");
        }

        URI invoker = invocation.getInvoker();

        if (invoker == null) {
            throw new BadID("Unknown invoker");
        }

        if (!invoker.equals(certificate.getSubject())) {
            throw new Invalid("Invoker and certificate's subject don't match");
        }

        List<BLSPublicKey> pks = new Stack<BLSPublicKey>();
        pks.add(resolver.resolve(invoker));

        List<byte[]> messages = new Stack<byte[]>();
        messages.add(invocation.getPayloadBytes());

        BLSSignature signature = BLS.signatureFromBytes(invocation.getSignature());

        verifyChain(pks, messages, signature, certificate, now);
    }

    private void verifyChain(List<BLSPublicKey> pks, List<byte[]> messages, BLSSignature signature, CapBACCertificate certificate, long now) throws Malformed, Expired, Invalid, BadID, BadSign {
        for (CapBACCertificate certificateInChain : certificate) {
            long expiration;
            CapBACCertificate parentCertificate;
            URI subject;
            URI issuer = certificateInChain.getIssuer();

            if ((expiration = certificateInChain.getExpiration()) != 0) {
                if (expiration < now) {
                    throw new Expired();
                }
            }

            if ((parentCertificate = certificateInChain.getParent()) != null) {
                subject = parentCertificate.getSubject();

                if (!subject.equals(issuer)) {
                    throw new Invalid(String.format("Issuer %s doesn't match subject of previous certificate in chain %s", issuer, subject));
                }
            }

            BLSPublicKey issuerPk = resolver.resolve(issuer);
            if (issuerPk == null) {
                throw new BadID(String.format("Unknown issuer %s", issuer));
            }

            pks.add(issuerPk);
            messages.add(certificateInChain.getPayloadBytes());
        }

        if (!BLS.aggregateVerify(pks, messages, signature)) {
            throw new BadSign("The invocation is malformed or changed.");
        }
    }
}
