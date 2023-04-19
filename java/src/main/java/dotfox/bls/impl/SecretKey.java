package dotfox.bls.impl;

public interface SecretKey {
    PublicKey derivePublicKey();

    Signature sign(byte[] message, String dst);

    /** Overwrites the key with zeros so that it is no longer in memory */
    void destroy();

    byte[] toBytes();
}
