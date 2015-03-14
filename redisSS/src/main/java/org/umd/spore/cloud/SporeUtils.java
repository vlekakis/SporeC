package org.umd.spore.cloud;

import com.yahoo.ycsb.ByteArrayByteIterator;
import com.yahoo.ycsb.ByteIterator;

import com.yahoo.ycsb.StringByteIterator;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.ArrayUtils;
import lombok.Data;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;


/**
 * @author vlekakis
 * Basic spore utils class that helps with
 *  - key generation
 *  - digital signatures 
 *  - read/write security keys to disk
 */

@Data
public class SporeUtils {
    

    private static final String SIGNATURE_RECORD_KEY = "signature";
    
    private String publicKeyPath;
    private String privateKeyPath;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Signature signObj;
    private Signature verifyObj;

    private int fieldLen;
    private int keyLen;
    private int signatureLength;
    private byte[] data;


    /**
     * Function to either load the keys from disk or to generate them.
     * The function generates them if while trying to find the keys get
     * and an Exception
     */
    public void loadKeys() {
        //Signature length the number of octets in the key

        signatureLength = keyLen / 8;
        data = new byte[2*(signatureLength+fieldLen)];
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
     * @param values The record to be signed
     * @return The record with all the fields now having a signature at their end
     * @throws Exception
     */
    public HashMap<String, ByteIterator> signFields(HashMap<String, ByteIterator>values) throws Exception {
        for (String s:values.keySet()) {
            ByteIterator valueIt = values.get(s);
            byte[] fieldBytes = valueIt.toArray();
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(fieldBytes);
            signObj.update(md5.digest());

            byte[] signature = signObj.sign();

            System.arraycopy(fieldBytes,0,data,0,fieldLen);
            System.arraycopy(signature,0,data,fieldLen,signatureLength);

            values.put(s,new ByteArrayByteIterator(data));
        }
        return values;
    }

    /**
     * Signature verification per field. It only returns true if all the fields are verified
     * @param result, data from the store
     * @return True if all the fields are verified
     * @throws Exception
     */
    public boolean verifySignatureOnFields(HashMap<String, ByteIterator> result) throws  Exception {

        for (String s:result.keySet()) {
            ByteIterator value = result.get(s);
            byte[] signedFieldBytes = value.toArray();


            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(signedFieldBytes,0,fieldLen);
            byte[] digest = md5.digest();
            verifyObj.update(digest);
            if (!verifyObj.verify(signedFieldBytes,fieldLen,signatureLength)) {
                return false;
            }
        }
        return true;
    }
    
    private void keyGeneration() {
        try {
            KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            pairGenerator.initialize(keyLen, random);
            
            KeyPair keyPair = pairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            saveKeys();

        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }

    private void printInputArrays(byte[] whole, byte[] field, byte[] digest, byte[]sign) {
        printByteArrayHex("whole: ", whole);
        printByteArrayHex("field: ", field);
        printByteArrayHex("digest: ", digest);
        printByteArrayHex("sign: ", sign);
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    }

    private void printByteArrayHex(String message, byte[] data) {
        System.out.println(message+"(size:"+data.length+") "+ DigestUtils.md5Hex(data));
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

