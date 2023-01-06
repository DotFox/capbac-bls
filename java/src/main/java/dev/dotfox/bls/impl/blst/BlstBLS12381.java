package dev.dotfox.bls.impl.blst;

import java.security.SecureRandom;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

import dev.dotfox.bls.impl.BLS12381;
import dev.dotfox.bls.impl.BlsException;
import dev.dotfox.bls.impl.PublicKey;
import dev.dotfox.bls.impl.SecretKey;
import dev.dotfox.bls.impl.Signature;
import supranational.blst.BLST_ERROR;
import supranational.blst.Pairing;

public class BlstBLS12381 implements BLS12381 {
    private static final SecureRandom RND = new SecureRandom();
    private static final String ciphersuite = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    private static Random getRND() {
        return RND;
    }

    public BlstSecretKey keyGen() {
        byte[] ikm = new byte[128];
        getRND().nextBytes(ikm);
        supranational.blst.SecretKey sk = new supranational.blst.SecretKey();
        sk.keygen(ikm);
        return new BlstSecretKey(sk);
    }

    public BlstPublicKey skToPk(SecretKey sk) {
        BlstSecretKey blst_sk = (BlstSecretKey)sk;
        return blst_sk.derivePublicKey();
    }

    public boolean keyValidate(PublicKey pk) {
        BlstPublicKey blst_pk = (BlstPublicKey) pk;
        return blst_pk.isValid();
    }

    public BlstSignature sign(SecretKey sk, byte[] message) {
        BlstSecretKey blst_sk = (BlstSecretKey) sk;
        return blst_sk.sign(message, ciphersuite);
    }

    public boolean verify(PublicKey pk, byte[] message, Signature signature) {
        BlstPublicKey blst_pk = (BlstPublicKey) pk;
        BlstSignature blst_signature = (BlstSignature) signature;
        BLST_ERROR res = blst_signature.point.core_verify(blst_pk.point, true, message, ciphersuite);
        return res == BLST_ERROR.BLST_SUCCESS;
    }

    public BlstSignature aggregate(List<? extends Signature> signatures) {
        return BlstSignature.aggregate(signatures.stream().map((Signature signature) -> (BlstSignature) signature).collect(Collectors.toList()));
    }

    public boolean aggregateVerify(List<? extends PublicKey> pks, List<byte[]> messages, Signature signature) {
        BlstSignature blst_signature = (BlstSignature) signature;

        boolean isAnyInfinity = pks.stream().anyMatch(pk -> ((BlstPublicKey) pk).isInfinity());
        if (isAnyInfinity) {
            return false;
        }

        if (pks.size() != messages.size()) {
            return false;
        }

        Pairing ctx = new Pairing(true, ciphersuite);

        for (int i = 0; i < pks.size(); i++) {
            BlstPublicKey pk = (BlstPublicKey) (pks.get(i));
            byte[] message = messages.get(i);
            BLST_ERROR ret = ctx.aggregate(pk.point, i == 0 ? blst_signature.point : null, message, new byte[0]);
            if (ret != BLST_ERROR.BLST_SUCCESS) {
                throw new BlsException("Error in Blst: " + ret);
            }
        }
        ctx.commit();
        return ctx.finalverify();
    }
}
