package dotfox.bls.impl;

public interface Signature {
    byte[] toBytes();

    /** Implementation must override */
    @Override
    int hashCode();

    /** Implementation must override */
    @Override
    boolean equals(Object obj);
}
