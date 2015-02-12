package umd.spore.cloud;

/**
 * Created by lex on 2/12/15.
 */

import org.apache.commons.io.FileUtils;
import org.junit.Test;
import org.junit.Assert;
import org.umd.spore.cloud.SporeUtils;

import java.io.File;

public class SporeUtilsTest {
    
    //TODO: signRecord test
    //TODO: signField test
    //TODO: vefifyField Test
    //TODO: vefiryRecord Test
    
    @Test
    public void testLoadKeysWithKeyGeneration() {
        System.out.println("testLoadKeysWithKeyGeneration");
        SporeUtils sp = new SporeUtils();
        sp.setPublicKeyPath("testFiles/public.key");
        sp.setPrivateKeyPath("testFiles/private.key");
        sp.loadKeys();

        Assert.assertNotNull(sp.getPublicKey());
        Assert.assertNotNull(sp.getPrivateKey());
        Assert.assertNotNull(sp.getSignObj());
        Assert.assertNotNull(sp.getVerifyObj());
        
        File f1 = new File("testFiles/public.key");
        File f2 = new File("testFiles/private.key");
        
        Assert.assertTrue(FileUtils.sizeOf(f1) > 0);
        Assert.assertTrue(FileUtils.sizeOf(f2) > 0);
        FileUtils.deleteQuietly(f1);
        FileUtils.deleteQuietly(f2);
    }


    @Test
    public void testLoadKeysLoadingFromDisk() {
        System.out.println("testLoadKeysLoadingFromDisk");
        SporeUtils sp = new SporeUtils();
        sp.setPublicKeyPath("testFiles/public2.key");
        sp.setPrivateKeyPath("testFiles/private2.key");
        sp.loadKeys();

        Assert.assertNotNull(sp.getPublicKey());
        Assert.assertNotNull(sp.getPrivateKey());
        Assert.assertNotNull(sp.getSignObj());
        Assert.assertNotNull(sp.getVerifyObj());
    }
}
