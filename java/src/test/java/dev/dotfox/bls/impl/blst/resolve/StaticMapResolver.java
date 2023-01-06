package dev.dotfox.bls.impl.blst.resolve;

import java.net.URI;
import java.util.Map;

import dev.dotfox.bls.BLSPublicKey;
import dev.dotfox.capbac.CapBACResolver;

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
