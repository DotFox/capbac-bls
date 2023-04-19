package dotfox.bls.impl.blst;

import dotfox.bls.impl.SecretKey;
import supranational.blst.P1;
import supranational.blst.P2;

public class BlstSecretKey implements SecretKey {
    private final supranational.blst.SecretKey secretKey;

    public BlstSecretKey(supranational.blst.SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public BlstSecretKey(byte[] secretKey) {
        supranational.blst.SecretKey sk = new supranational.blst.SecretKey();
        sk.from_bendian(secretKey);
        this.secretKey = sk;
    }

    public byte[] toBytes() {
        return secretKey.to_bendian();
    }

    public supranational.blst.SecretKey getKey() {
        return secretKey;
    }

    public BlstPublicKey derivePublicKey() {
        P1 pk = new P1(secretKey);
        return new BlstPublicKey(pk.to_affine());
    }

    public BlstSignature sign(byte[] message, String dst) {
        P2 p2 = new P2();
        p2.hash_to(message, dst, new byte[0]).sign_with(this.getKey());
        return new BlstSignature(p2.to_affine());
    }

    public void destroy() {
        secretKey.from_bendian(new byte[32]);
    }
}
