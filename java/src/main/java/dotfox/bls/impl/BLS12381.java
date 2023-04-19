package dotfox.bls.impl;

import java.util.List;

public interface BLS12381 {
    SecretKey keyGen();

    PublicKey skToPk(SecretKey sk);

    boolean keyValidate(PublicKey pk);

    Signature sign(SecretKey sk, byte[] message);

    boolean verify(PublicKey pk, byte[] message, Signature signature);

    Signature aggregate(List<? extends Signature> signatures);

    boolean aggregateVerify(List<? extends PublicKey> pks, List<byte[]> messages, Signature signature);
}
