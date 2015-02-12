package org.umd.spore.cloud;

import com.yahoo.ycsb.ByteArrayByteIterator;
import com.yahoo.ycsb.ByteIterator;
import com.yahoo.ycsb.StringByteIterator;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.ArrayUtils;
import lombok.Data;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

/**
 * @author vlekakis
 * Basic spore utils class that helps with
 *  - key generation
 *  - digital signatures 
 *  - read/write security keys to disk
 */

@Data
public class SporeUtils {
    
    private String publicKeyPath;
    private String privateKeyPath;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Signature signObj;
    private Signature verifyObj;

    /**
     * Function to either load the keys from disk or to generate them.
     * The function generates them if while trying to find the keys get
     * and an Exception
     */
    public void loadKeys() {
        try {
            readKeys();
        } catch (Exception e) {
            keyGeneration();
        }
        try {
            signObj = Signature.getInstance("SHA1withRSA");
            verifyObj = Signature.getInstance("SHA1withRSA");
            signObj.initSign(privateKey);
            verifyObj.initVerify(publicKey);
        } catch (Exception signCreation) {
            System.out.println(signCreation.getMessage());
            signCreation.printStackTrace();
        }
    }
    

    /**
     * 
     * Record-based signature
     *
     * @param values The record to be inserted in the data store
     * @return The record with an extra field that represents the signature of the record
     * @throws Exception
     */
    public Map<String, ByteIterator> signRecord(Map<String, ByteIterator>values) throws Exception {
        byte[] mapBytes = StringByteIterator.getStringMap(values).toString().getBytes();
        signObj.update(mapBytes);
        values.put("sign", new ByteArrayByteIterator(signObj.sign()));
        return values;
    }

    /**
     * 
     * @param values The record to be signed
     * @return The record with all the fields now having a signature at their end
     * @throws Exception
     */
    public Map<String, ByteIterator> signFields(Map<String, ByteIterator>values) throws Exception {
        for (String s:values.keySet()) {
            ByteIterator valueIt = values.get(s);
            byte[] fieldBytes = valueIt.toArray();
            signObj.update(fieldBytes);
            byte[] signature = signObj.sign();
            byte[] signedField = ArrayUtils.addAll(fieldBytes, signature);
            values.put(s,new ByteArrayByteIterator(signedField));
        }
        return values;
    }

    /**
     * This function looks the whole record and checks if it is verified
     * The signature bytes are placed in a new field
     *
     * @param result Contains the data read from the store
     * @return True or False based on the signature verification
     * @throws Exception
     */
    public boolean verifySignatureRecord(Map<String, ByteIterator> result) throws Exception {
        boolean verificationResult = false;
        if (result == null) {
            return true;
        }
        byte[] signature = result.get("sign").toArray();
        result.remove("sign");
        byte[] resultBytes = StringByteIterator.getStringMap(result).toString().getBytes();
        verifyObj.update(resultBytes);
        verificationResult = verifyObj.verify(signature);
        return verificationResult;
    }

    /**
     * Signature verification per field. It only returns true if all the fields are verified
     * @param result, data from the store
     * @param fieldSize, data size to find the beginning of the signature
     * @return True if all the fields are verified
     * @throws Exception
     */
    public boolean verifySignatureOnFields(Map<String, ByteIterator> result, int fieldSize) throws  Exception {
        boolean verificationResult = false;
        
        for (String s:result.keySet()) {
            ByteIterator value = result.get(s);
            byte[] signedFieldBytes = value.toArray();
            byte[] fieldBytes = ArrayUtils.subarray(signedFieldBytes, 0, fieldSize);
            byte[] signature = ArrayUtils.subarray(signedFieldBytes, fieldSize, signedFieldBytes.length);
            verifyObj.update(fieldBytes);
            verificationResult = verifyObj.verify(signature);
            if (!verificationResult) {
                return false;
            }
        }
        return true;
    }
    
    private void keyGeneration() {
        try {
            KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            pairGenerator.initialize(1024, random);
            
            KeyPair keyPair = pairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            saveKeys();

        } catch (Exception e) {

        }
    }
    
    
    private void saveKeys() throws IOException{
        if (StringUtils.isNotBlank(publicKeyPath)) {
            saveKeyBytes(publicKey.getEncoded(), publicKeyPath);
        }
        if (StringUtils.isNotBlank(privateKeyPath)) {
            saveKeyBytes(privateKey.getEncoded(), privateKeyPath);
        }
    }
    
    private void readKeys() throws Exception {
        byte[] keyBytes;
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        if (StringUtils.isNotBlank(publicKeyPath)) {
            keyBytes = readKeyBytes(publicKeyPath);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = keyFactory.generatePublic(pubKeySpec);
        }
        if (StringUtils.isNotBlank(privateKeyPath)) {
            keyBytes = readKeyBytes(privateKeyPath);
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            privateKey = keyFactory.generatePrivate(privKeySpec);

        }
    }
    
    private void saveKeyBytes(byte[] keyBytes, String path) throws IOException {
        FileOutputStream fOut = new FileOutputStream(path);
        fOut.write(keyBytes);
        fOut.close();
    }
    
    private byte[] readKeyBytes(String path) throws IOException {
        FileInputStream fIn = new FileInputStream(path);
        byte[] keyBytes = new byte[fIn.available()];
        fIn.read(keyBytes);
        fIn.close();
        return keyBytes;
    }

}

