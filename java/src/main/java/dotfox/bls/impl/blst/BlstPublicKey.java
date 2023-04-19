package dotfox.bls.impl.blst;

import dotfox.bls.impl.PublicKey;
import supranational.blst.P1_Affine;

public class BlstPublicKey implements PublicKey {
    final P1_Affine point;

    public BlstPublicKey(P1_Affine point) {
        this.point = point;
    }

    public BlstPublicKey(byte[] point) {
        this.point = new P1_Affine(point);
    }

    public byte[] toBytes() {
        return point.compress();
    }

    public boolean isInfinity() {
        return point.is_inf();
    }

    public boolean isInGroup() {
        return point.in_group();
    }
    
    public boolean isValid() {
        return !isInfinity() && isInGroup();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((point == null) ? 0 : point.hashCode());
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
        BlstPublicKey other = (BlstPublicKey) obj;
        if (point == null) {
            if (other.point != null)
                return false;
        } else if (!point.is_equal(other.point))
            return false;
        return true;
    }
}
