package org.umd.spore.cloud.utility;


import org.testng.annotations.Test;

import java.security.PrivateKey;


/**
 * Created by lex on 8/4/15.
 */
public class TestHmacGenerator {

    @Test
    public void testHmacGenerator() {
        Signer s = new Signer();
        s.setKeyLen(512);
        s.keyGeneration();
        PrivateKey priv = s.getPrivateKey();
        String res = HMACTag.calculate("data", priv);
    }
}
