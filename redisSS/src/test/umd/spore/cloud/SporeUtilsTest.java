package umd.spore.cloud;

/**
 * Created by lex on 2/12/15.
 */

import com.yahoo.ycsb.ByteIterator;
import com.yahoo.ycsb.RandomByteIterator;
import com.yahoo.ycsb.StringByteIterator;
import org.apache.commons.io.FileUtils;
import org.junit.Test;
import org.junit.Assert;
import org.umd.spore.cloud.SporeUtils;

import java.io.File;
import java.util.Map;
import java.util.HashMap;

public class SporeUtilsTest {

    //TODO: vefifyField Test
    //TODO: vefiryRecord Test
    
    private static final String PRIVATE_PATH = "testFiles/private2.key";
    private static final String PUBLIC_PATH = "testFiles/public2.key";
    
    @Test
    public void testSignVerifyRecordSingleField() {
        try {

            SporeUtils sp = new SporeUtils();
            sp.setPublicKeyPath(PUBLIC_PATH);
            sp.setPrivateKeyPath(PRIVATE_PATH);
            sp.loadKeys();

            
            Map<String, ByteIterator>record = new HashMap<String, ByteIterator>(1);
            String val = "value";
            record.put("record", new StringByteIterator(val));
            
            record = sp.signFields(record);
            boolean res = sp.verifySignatureOnFields(record, val.length());
            Assert.assertTrue(res);
            
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
        
    }
    
    @Test
    public void testSignVerifyRecordMultipleFields() {
        System.out.println("testing.....testSignVerifyRecordMultipleFields" );
        try {
            SporeUtils sp = new SporeUtils();
            sp.setPublicKeyPath("testFiles/public2.key");
            sp.setPrivateKeyPath("testFiles/private2.key");
            sp.loadKeys();
            
            int numFields = 20;
            int sizeFields = 100;
            Map<String, ByteIterator> record = new HashMap<String, ByteIterator>(numFields);
            for (int i=0; i<numFields; i++) {
                record.put(Integer.valueOf(i).toString(), new RandomByteIterator(sizeFields));
            }
            record = sp.signFields(record);
            boolean res = sp.verifySignatureOnFields(record, sizeFields);
            Assert.assertTrue(res);


        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
        
    }
    
    
    @Test
    public void testLoadKeysWithKeyGeneration() {
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
