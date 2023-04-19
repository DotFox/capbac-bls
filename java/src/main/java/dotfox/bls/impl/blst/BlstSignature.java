package dotfox.bls.impl.blst;

import java.util.List;

import dotfox.bls.impl.BlsException;
import dotfox.bls.impl.Signature;
import supranational.blst.P2;
import supranational.blst.P2_Affine;

public class BlstSignature implements Signature {
    final P2_Affine point;

    public BlstSignature(P2_Affine point) {
        this.point = point;
    }

    public BlstSignature(byte[] point) {
        this.point = new P2_Affine(point);
    }

    public byte[] toBytes() {
        return point.compress();
    }

    public static BlstSignature aggregate(List<BlstSignature> signatures) {
        try {
            P2 sum = new P2();
            for (BlstSignature signature : signatures) {
                sum.aggregate(signature.point);
            }
            return new BlstSignature(sum.to_affine());
        } catch (IllegalArgumentException e) {
            throw new BlsException("Signature aggregation failed", e);
        }
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
        BlstSignature other = (BlstSignature) obj;
        if (point == null) {
            if (other.point != null)
                return false;
        } else if (!point.is_equal(other.point))
            return false;
        return true;
    }
}
