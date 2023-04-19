package dotfox.bls;

import dotfox.bls.impl.SecretKey;

public class BLSSecretKey {
    private final SecretKey sk;

    public SecretKey getSk() {
        return sk;
    }

    public BLSSecretKey(SecretKey sk) {
        this.sk = sk;
    }
}
