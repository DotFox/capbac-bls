package dotfox.bls.impl.blst.resolve;

import java.net.URI;
import java.util.Map;

import dotfox.bls.BLSPublicKey;
import dotfox.capbac.CapBACResolver;

public class StaticMapResolver implements CapBACResolver {
    private Map<URI, BLSPublicKey> map;

    public StaticMapResolver(Map<URI, BLSPublicKey> map) {
        this.map = map;
    }

    @Override
    public BLSPublicKey resolve(URI id) {
        return map.get(id);
    }
}
