/**
 * Redis client binding for YCSB.
 *
 * All YCSB records are mapped to a Redis *hash field*.  For scanning
 * operations, all keys are saved (by an arbitrary hash) in a sorted set.
 */

package com.yahoo.ycsb.db;
import com.yahoo.ycsb.*;

import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;

import com.yahoo.ycsb.measurements.Measurements;
import org.apache.commons.lang3.StringUtils;
import org.umd.spore.cloud.SporeStrings;
import org.umd.spore.cloud.SporeUtils;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.Protocol;

public class RedisSimpleSignatureClient extends DB {

    private Jedis jedis;
    private SporeUtils sporeSignatures;
    
    public static final String HOST_PROPERTY = "redis.host";
    public static final String PORT_PROPERTY = "redis.port";
    public static final String PASSWORD_PROPERTY = "redis.password";


    public static final String INDEX_KEY = "_indices";

    public void init() throws DBException {
        Properties props = getProperties();
        int port;

        String portString = props.getProperty(PORT_PROPERTY);
        if (portString != null) {
            port = Integer.parseInt(portString);
        }
        else {
            port = Protocol.DEFAULT_PORT;
        }
        String host = props.getProperty(HOST_PROPERTY);
        

        jedis = new Jedis(host, port);
        jedis.connect();

        String password = props.getProperty(PASSWORD_PROPERTY);
        if (password != null) {
            jedis.auth(password);
        }
        
        /*
            Setup spore utils for signatures 
         */
        String publicKeyPath = props.getProperty(SporeStrings.PUBLIC_KEY_PATH);
        if (StringUtils.isBlank(publicKeyPath)) {
            publicKeyPath = SporeStrings.DEFAULT_PUBLIC_KEY_PATH;
        }
        String privateKeyPath = props.getProperty(SporeStrings.PRIVATE_KEY_PATH);
        if (StringUtils.isBlank(privateKeyPath)) {
            privateKeyPath = SporeStrings.DEFAULT_PRIVATE_KEY_PATH;
        }


        sporeSignatures = new SporeUtils();
        sporeSignatures.setPublicKeyPath(publicKeyPath);
        sporeSignatures.setPrivateKeyPath(privateKeyPath);
        sporeSignatures.setKeyLen(1024);
        sporeSignatures.loadKeys();
    }

    public void cleanup() throws DBException {
        jedis.disconnect();
    }

    /* Calculate a hash for a key to store it in an index.  The actual return
     * value of this function is not interesting -- it primarily needs to be
     * fast and scattered along the whole space of doubles.  In a real world
     * scenario one would probably use the ASCII values of the keys.
     */
    private double hash(String key) {
        return key.hashCode();
    }

    //XXX jedis.select(int index) to switch to `table`

    @Override
    public int read(String table, String key, Set<String> fields,
                    HashMap<String, ByteIterator> result) {
        
        long stRead = System.currentTimeMillis();
        if (fields == null) {
            StringByteIterator.putAllAsByteIterators(result, jedis.hgetAll(key));
        }
        else {
            String[] fieldArray = (String[])fields.toArray(new String[fields.size()]);
            List<String> values = jedis.hmget(key, fieldArray);

            Iterator<String> fieldIterator = fields.iterator();
            Iterator<String> valueIterator = values.iterator();

            while (fieldIterator.hasNext() && valueIterator.hasNext()) {
                result.put(fieldIterator.next(),
                        new StringByteIterator(valueIterator.next()));
            }
            assert !fieldIterator.hasNext() && !valueIterator.hasNext();
        }
        long enRead = System.currentTimeMillis();
        Measurements.getMeasurements().measure(SporeStrings.REDIS_SS_READ, (int)(enRead-stRead));


        try {
            long stVerify = System.currentTimeMillis();
            boolean verifySign = sporeSignatures.verifySignatureOnFields(result);
            if (!verifySign) {
                throw new RuntimeException("Signature verification");
            }
            long enVerify = System.currentTimeMillis();
            Measurements.getMeasurements().measure(SporeStrings.REDIS_SS_VERIRY_FIELDS, (int)(enVerify-stVerify));
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
        
        return result.isEmpty() ? 1 : 0;
    }

    @Override
    public int insert(String table, String key, HashMap<String, ByteIterator> values) {
        try {
            long stSign = System.currentTimeMillis();
            values = sporeSignatures.signFields(values);
            long enSign = System.currentTimeMillis();
            Measurements.getMeasurements().measure(SporeStrings.REDIS_SS_SIGN_FIELDS, (int)(enSign-stSign));
            
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            return  1;
        }
        long stInsert;
        long enInsert;
        stInsert = System.currentTimeMillis();
        if (jedis.hmset(key, StringByteIterator.getStringMap(values)).equals("OK")) {
            jedis.zadd(INDEX_KEY, hash(key), key);
            enInsert = System.currentTimeMillis();
            Measurements.getMeasurements().measure(SporeStrings.REDIS_SS_SIGN_FIELDS, (int)(enInsert-stInsert));
            return 0;
        }
        enInsert = System.currentTimeMillis();
        Measurements.getMeasurements().measure(SporeStrings.REDIS_SS_SIGN_FIELDS, (int)(enInsert-stInsert));
        return 1;
    }

    @Override
    public int delete(String table, String key) {
        return jedis.del(key) == 0
                && jedis.zrem(INDEX_KEY, key) == 0
                ? 1 : 0;
    }

    @Override
    public int update(String table, String key, HashMap<String, ByteIterator> values) {
        try {
            long stSign = System.currentTimeMillis();
            values = sporeSignatures.signFields(values);
            long enSign = System.currentTimeMillis();
            Measurements.getMeasurements().measure(SporeStrings.REDIS_SS_SIGN_FIELDS, (int)(enSign-stSign));
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            return 1;
        }


        long stUpdate = System.currentTimeMillis();
        int res = jedis.hmset(key, StringByteIterator.getStringMap(values)).equals("OK") ? 0 : 1;
        long enUpdate = System.currentTimeMillis();
        Measurements.getMeasurements().measure(SporeStrings.REDIS_SS_UPDATE, (int)(enUpdate-stUpdate));
        return res;
    }

    @Override
    public int scan(String table, String startkey, int recordcount,
                    Set<String> fields, Vector<HashMap<String, ByteIterator>> result) {
        Set<String> keys = jedis.zrangeByScore(INDEX_KEY, hash(startkey),
                Double.POSITIVE_INFINITY, 0, recordcount);

        HashMap<String, ByteIterator> values;
        for (String key : keys) {
            values = new HashMap<String, ByteIterator>();
            read(table, key, fields, values);
            result.add(values);
        }

        return 0;
    }

}
