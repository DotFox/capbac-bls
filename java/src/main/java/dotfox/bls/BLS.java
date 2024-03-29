package dotfox.bls;

import java.util.List;
import java.util.Arrays;
import java.util.stream.Collectors;

import dotfox.bls.impl.BLS12381;
import dotfox.bls.impl.BlsException;
import dotfox.bls.impl.blst.BlstLoader;
import dotfox.bls.impl.blst.BlstPublicKey;
import dotfox.bls.impl.blst.BlstSignature;

public class BLS {
    private static BLS12381 impl;

    static {
        resetBlsImplementation();
    }

    private static void resetBlsImplementation() {
        if (BlstLoader.INSTANCE.isPresent()) {
            impl = BlstLoader.INSTANCE.get();
        } else {
            throw new BlsException("Failed to load Blst library.");
        }
    }

    public static BLSKeyPair keyGen() {
        BLSSecretKey sk = new BLSSecretKey(impl.keyGen());
        BLSPublicKey pk = new BLSPublicKey(impl.skToPk(sk.getSk()));
        return new BLSKeyPair(sk, pk);
    }

    public static BLSSignature sign(BLSSecretKey sk, byte[] message) {
        return new BLSSignature(impl.sign(sk.getSk(), message));
    }

    public static BLSSignature aggregate(List<? extends BLSSignature> signatures) {
        return new BLSSignature(impl.aggregate(signatures.stream().map((BLSSignature sign) -> sign.getSignature()).collect(Collectors.toList())));
    }

    public static BLSSignature signAndAggregate(BLSSecretKey sk, byte[] message, BLSSignature aggregatedSignature) {
        BLSSignature signature = sign(sk, message);
        return aggregate(Arrays.asList(aggregatedSignature, signature));
    }

    public static boolean aggregateVerify(List<? extends BLSPublicKey> pks, List<byte[]> messages, BLSSignature sign) {
        return impl.aggregateVerify(pks.stream().map((BLSPublicKey pk) -> pk.getPk()).collect(Collectors.toList()),
                                    messages,
                                    sign.getSignature());
    }

    public static BLSSignature signatureFromBytes(byte[] payload) {
        return new BLSSignature(new BlstSignature(payload));
    }

    public static BLSPublicKey pkFromBytes(byte[] payload) {
        return new BLSPublicKey(new BlstPublicKey(payload));
    }
}
