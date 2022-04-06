package anotherVariant;


import org.junit.Before;
import org.junit.Test;

import java.security.Key;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by lake on 17-4-12.
 */
public class RSACoderTest {
    private String publicKey;
    private String privateKey;

    @Before
    public void setUp() throws Exception {
        Map<String, Key> keyMap = RSACoder.initKey();
        publicKey = RSACoder.getPublicKey(keyMap);
        privateKey = RSACoder.getPrivateKey(keyMap);

        publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBO71iVLEu7umehJ0HJ5501wW1rSKTL3hkng+WRJZCnQ/3ZWLJrdLdgRRkaQMpzdF+AmqvtioluXjZdyrhLpkRtcAkjgQbBnRnL5zirJydmYZJU8CRSjrrER439hHTD9Zml1y9Pa//NPcfnd9iw6kZSX5rArEzFiKp3hRZGgecYwIDAQAB";
        privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAME7vWJUsS7u6Z6EnQcnnnTXBbWtIpMveGSeD5ZElkKdD/dlYsmt0t2BFGRpAynN0X4Caq+2KiW5eNl3KuEumRG1wCSOBBsGdGcvnOKsnJ2ZhklTwJFKOusRHjf2EdMP1maXXL09r/809x+d32LDqRlJfmsCsTMWIqneFFkaB5xjAgMBAAECgYEAm4K/hI5SVkoyO7/QPDzXWoLd9ntTEw8mHhvSwYWLRCrw+ZJfsZ2x0VAboD+fKxqYGYhKYgUB4IBm0OUF3lnJF0CmzWYcPg7QpsNRU2iCp50c6EyGmNItpPQycnTx68xG1RTYE1EXfwAmHDeB9Bbsk87HHdJQqjANnUFeSDPq9/ECQQDelkKO7rZA/KNKmQJZIqGEGWvlMb+5SuHCiVRLT3vqKuaub0Fym1Ey6ngVYN5yZt2tnUV6brfwr+/y3TyQlq0pAkEA3j11Ju32DsAzC4dtmDM4vee8KY7OpnE2dkEGA9K6U8M/R3y3WQEtUC8kqf+m9EXOdiMlB72Ld0N0TojQ+R6iqwJAMcDShdJz6JjQAyeqb7Qe+EEabfOt0EQdrHc34VGV+CS4xXrW3UA8aS4hw12Qu2+k017ZHeHLucAJ2XZ8SDF16QJAE+woe2Proeji6o6qaXF2Dbgfaw5NQih1/GXZ1y/l2ipvmsX4Xbc4S67eN4seeVlkp7yAzk/Ul81pOL0VFrADXwJBAI/2Oq2AcSNOu6QY3JuzU4kN1mjKGDkBqmV3nHev9bp7NLyoasqzg8xo9lvuYjPpo47JXPgpH+CXXkLTTmqk/m8=";

        System.err.println(" The public key : \n\r" + publicKey);
        System.err.println(" The private key:  \n\r" + privateKey);
    }

    @Test
    public void decrypt() throws Exception {
        String decrypted = "fgPVk5suQDbJrVsVKX7dpSo4xPDi4UXyF2oBZ4yusvObMdDeq+4ckqKMU685egz+Tzla4/FjNYOTbxJj1nddB4Ef1P+gJF1l76SLwqvR/LrHEq2vlO5Mn0hrmVKQS5dbDRnqZKBchDCqfICFf6CZYBAxRezEs9hHsl/j/gBGaLI=";
        byte[] decryptedBytes = decrypted.getBytes();
        byte[] decodedData = RSACoder.decryptByPrivateKey(decryptedBytes,
                privateKey);
        String outputStr = new String(decodedData);
    }

    @Test
    public void test() throws Exception {
        System.err.println(" Public key encryption - Private key decryption ");
        String inputStr = "128939";
        byte[] encodedData = RSACoder.encryptByPublicKey(inputStr, publicKey);

        String res = new String(encodedData);
        System.out.println(" Encrypted String: \n\r" + res);
        System.out.println(" length: " + res.length());

        byte[] decodedData = RSACoder.decryptByPrivateKey(encodedData,
                privateKey);
        String outputStr = new String(decodedData);
        System.err.println(" Before the encryption : " + inputStr + "\n\r" + " decrypted : " + outputStr);
        assertEquals(inputStr, outputStr);
    }

    @Test
    public void testSign() throws Exception {
        System.err.println(" Private key encryption -- public key decryption ");
        String inputStr = "sign";
        byte[] data = inputStr.getBytes();
        byte[] encodedData = RSACoder.encryptByPrivateKey(data, privateKey);
        byte[] decodedData = RSACoder.decryptByPublicKey(encodedData, publicKey);
        String outputStr = new String(decodedData);
        System.err.println(" Before the encryption : " + inputStr + "\n\r" + " decrypted : " + outputStr);
        assertEquals(inputStr, outputStr);
        System.err.println(" Private key signature - The public key validates the signature ");
        //  Generate the signature
        String sign = RSACoder.sign(encodedData, privateKey);
        System.err.println(" The signature :" + sign);
        //  Verify the signature
        boolean status = RSACoder.verify(encodedData, publicKey, sign);
        System.err.println(" state :" + status);
        assertTrue(status);
    }
}

