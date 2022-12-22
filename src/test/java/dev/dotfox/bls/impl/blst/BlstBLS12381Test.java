package dev.dotfox.bls.impl.blst;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import dev.dotfox.bls.BLS;
import dev.dotfox.bls.BLSKeyPair;
import dev.dotfox.bls.BLSPublicKey;
import dev.dotfox.bls.impl.blst.resolve.StaticMapResolver;
import dev.dotfox.bls.impl.blst.trust.PatternChecker;
import dev.dotfox.capbac.CapBACCertificate;
import dev.dotfox.capbac.CapBACHolder;
import dev.dotfox.capbac.CapBACInvocation;
import dev.dotfox.capbac.CapBACResolver;
import dev.dotfox.capbac.CapBACTrustChecker;
import dev.dotfox.capbac.CapBACValidator;
import dev.dotfox.capbac.CapBAC.BadID;
import dev.dotfox.capbac.CapBAC.BadSign;
import dev.dotfox.capbac.CapBAC.Expired;
import dev.dotfox.capbac.CapBAC.Invalid;
import dev.dotfox.capbac.CapBAC.Malformed;
import dev.dotfox.capbac.CapBACCertificate.Builder;

import org.junit.Test;

/**
 * Unit test for simple App.
 */
public class BlstBLS12381Test
{
    /**
     * Rigorous Test :-)
     */
    @Test
    public void shouldAnswerWithTrue()
    {
        BLSKeyPair key_pair1 = BLS.keyGen();
        CapBACHolder holder1 = new CapBACHolder(URI.create("local://me"), key_pair1.getSk());
        CapBACCertificate cert1 = holder1.forge("everything".getBytes(UTF_8));
        CapBACCertificate cert2 = holder1.delegate(cert1, new Builder(URI.create("local://notme"), "something".getBytes(UTF_8)));

        BLSKeyPair key_pair2 = BLS.keyGen();
        CapBACHolder holder2 = new CapBACHolder(URI.create("local://notme"), key_pair2.getSk());
        CapBACCertificate cert3 = holder2.delegate(cert2, new Builder(URI.create("local://alisa"), new byte[16]));

        // Totally legit invocation
        CapBACInvocation inv1 = holder2.invoke(cert2, "fire!".getBytes(UTF_8));

        // Let's pretend holder2 is trying to use someone elses certificate
        // to invoke some action
        CapBACInvocation inv2 = holder2.invoke(cert3, "fire!".getBytes(UTF_8));

        Map<URI, BLSPublicKey> resolverStore = new HashMap<URI, BLSPublicKey>();
        resolverStore.put(URI.create("local://me"), key_pair1.getPk());
        resolverStore.put(URI.create("local://notme"), key_pair2.getPk());

        CapBACTrustChecker patternChecker = new PatternChecker(Pattern.compile("local://me"));
        CapBACResolver mapResolver = new StaticMapResolver(resolverStore);

        CapBACValidator validator = new CapBACValidator(patternChecker, mapResolver);

        try {
            // All good :)
            validator.validate(inv1, 10);
            System.out.println("OK");
            // next line will throw indicating
            // that invoker is not the same entity who holds certificate
            validator.validate(inv2, 10);
            System.out.println("Not OK");
        } catch (Invalid | Expired | BadID | BadSign | Malformed e) {
            e.printStackTrace();
        }

        assertTrue( true );
    }
}
