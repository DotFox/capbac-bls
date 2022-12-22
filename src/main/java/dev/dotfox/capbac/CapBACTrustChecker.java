package dev.dotfox.capbac;

import java.net.URI;

public interface CapBACTrustChecker {
    boolean check(URI id);
}
