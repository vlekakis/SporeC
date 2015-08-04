package org.umd.spore.cloud.utility;


import javax.crypto.Mac;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.HmacUtils;
import java.security.Key;

/**
 * @author vlekakis
 * Basic hmac generation for given data
 *  - calculaing the hmac
 */


public class HMACTag {

    private static final String HMAC_ALGORITHM = "HmacSHA1";

    public static String calculate(String data, Key key) throws SecurityException {
        try {

            Mac mac = HmacUtils.getInitializedMac(HMAC_ALGORITHM, key.getEncoded());
            byte[] hmacBytes = mac.doFinal(data.getBytes());
            String result = Base64.encodeBase64String(hmacBytes);
            return result;

        } catch (Exception e) {

            throw new RuntimeException(e);
        }
    }

}
