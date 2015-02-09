package org.umd.spore.cloud;

import com.yahoo.ycsb.ByteIterator;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author vlekakis
 * Basic spore utils class that helps with
 *  - key generation
 *  - digital signatures 
 *  - read/write keys to disk
 */

@Data
public class SporeUtils {
    
    private String publicKeyPath;
    private String privateKeyPath;
    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    
    public void loadKeys() {
        try {
            readKeys();
        } catch (Exception e) {
            keyGeneration();
        }
    }
    
    //TODO: single field sign
    //TODO: record signature
    //TODO: verification of record
    //TODO: verification of field
    
    
    private void keyGeneration() {
        try {
            KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA", "SUN");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            pairGenerator.initialize(1024, random);
            
            keyPair = pairGenerator.generateKeyPair();
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
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SUN");
        
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

