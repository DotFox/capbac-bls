package dotfox.capbac;

import java.net.URI;

import dotfox.bls.BLS;
import dotfox.bls.BLSSecretKey;
import dotfox.bls.BLSSignature;

public class CapBACHolder {
    final URI me;
    private final BLSSecretKey sk;

    public CapBACHolder(URI me, BLSSecretKey sk) {
        this.me = me;
        this.sk = sk;
    }

    public CapBACCertificate forge(byte[] capability) {
        return new CapBACCertificate(new CapBACCertificate.Builder(me, capability), this);
    }

    public CapBACCertificate delegate(CapBACCertificate cert, CapBACCertificate.Builder builder) {
        return new CapBACCertificate(cert, builder, this);
    }

    public CapBACCertificate delegate(CapBACCertificate certificate, byte[] capability) {
        return delegate(certificate, new CapBACCertificate.Builder(me, capability));
    }

    public CapBACInvocation invoke(CapBACCertificate certificate, CapBACInvocation.Builder builder) {
        return new CapBACInvocation(certificate, builder, this);
    }

    public CapBACInvocation invoke(CapBACCertificate certificate, byte[] action) {
        return invoke(certificate, new CapBACInvocation.Builder(action));
    }

    BLSSignature sign(byte[] payload) {
        return BLS.sign(sk, payload);
    }

    BLSSignature sign(byte[] payload, BLSSignature aggregateSoFar) {
        return BLS.signAndAggregate(sk, payload, aggregateSoFar);
    }

    BLSSignature sign(byte[] payload, byte[] aggregateSoFar) {
        if (aggregateSoFar == null) {
            return sign(payload);
        }
        return sign(payload, BLS.signatureFromBytes(aggregateSoFar));
    }
}
