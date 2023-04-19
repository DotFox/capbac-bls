package dotfox.bls.impl;

public interface PublicKey {
    byte[] toBytes();
    /**
     * Determine if the key is valid.
     *
     * @return true if the key is valid, otherwise false.
     */
    boolean isValid();

    /** Implementation must override */
    @Override
    int hashCode();

    /** Implementation must override */
    @Override
    boolean equals(Object obj);
}
