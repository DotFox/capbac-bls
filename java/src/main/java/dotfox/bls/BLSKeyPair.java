package dotfox.bls;

public class BLSKeyPair {
    private final BLSSecretKey sk;
    private final BLSPublicKey pk;

    BLSKeyPair(BLSSecretKey sk, BLSPublicKey pk) {
        this.sk = sk;
        this.pk = pk;
    }

    public BLSPublicKey getPk() {
        return pk;
    }

    public BLSSecretKey getSk() {
        return sk;
    }
}
