package dotfox.bls;

import dotfox.bls.impl.PublicKey;

public class BLSPublicKey {
    private final PublicKey pk;

    public PublicKey getPk() {
        return pk;
    }

    BLSPublicKey(PublicKey pk) {
        this.pk = pk;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((pk == null) ? 0 : pk.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        BLSPublicKey other = (BLSPublicKey) obj;
        if (pk == null) {
            if (other.pk != null)
                return false;
        } else if (!pk.equals(other.pk))
            return false;
        return true;
    }
}
