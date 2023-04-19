package dotfox.bls.impl.blst.trust;

import dotfox.capbac.CapBACTrustChecker;

import java.net.URI;
import java.util.regex.Pattern;

public class PatternChecker implements CapBACTrustChecker {
    private Pattern pattern;

    public PatternChecker(Pattern pattern) {
        this.pattern = pattern;
    }

    @Override
    public boolean check(URI id) {
        return pattern.matcher(id.toString()).matches();
    }
}
