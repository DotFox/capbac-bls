package dotfox.capbac;

import java.net.URI;

import dotfox.bls.BLSPublicKey;

public interface CapBACResolver {
    BLSPublicKey resolve(URI id);
}
