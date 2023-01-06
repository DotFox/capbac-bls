package dev.dotfox.capbac;

import java.net.URI;

import dev.dotfox.bls.BLSPublicKey;

public interface CapBACResolver {
    BLSPublicKey resolve(URI id);
}
