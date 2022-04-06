import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.util.encoders.Base64;

public class RSABase64Test {

    private static final String ALGORITHM = "RSA";

    private static final String NONE_PADDING = "RSA/None/PKCS1Padding";

    private static final Provider pro = new BouncyCastleProvider();

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        String privateCheckKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAME7vWJUsS7u6Z6EnQcnnnTXBbWtIpMveGSeD5ZElkKdD/dlYsmt0t2BFGRpAynN0X4Caq+2KiW5eNl3KuEumRG1wCSOBBsGdGcvnOKsnJ2ZhklTwJFKOusRHjf2EdMP1maXXL09r/809x+d32LDqRlJfmsCsTMWIqneFFkaB5xjAgMBAAECgYEAm4K/hI5SVkoyO7/QPDzXWoLd9ntTEw8mHhvSwYWLRCrw+ZJfsZ2x0VAboD+fKxqYGYhKYgUB4IBm0OUF3lnJF0CmzWYcPg7QpsNRU2iCp50c6EyGmNItpPQycnTx68xG1RTYE1EXfwAmHDeB9Bbsk87HHdJQqjANnUFeSDPq9/ECQQDelkKO7rZA/KNKmQJZIqGEGWvlMb+5SuHCiVRLT3vqKuaub0Fym1Ey6ngVYN5yZt2tnUV6brfwr+/y3TyQlq0pAkEA3j11Ju32DsAzC4dtmDM4vee8KY7OpnE2dkEGA9K6U8M/R3y3WQEtUC8kqf+m9EXOdiMlB72Ld0N0TojQ+R6iqwJAMcDShdJz6JjQAyeqb7Qe+EEabfOt0EQdrHc34VGV+CS4xXrW3UA8aS4hw12Qu2+k017ZHeHLucAJ2XZ8SDF16QJAE+woe2Proeji6o6qaXF2Dbgfaw5NQih1/GXZ1y/l2ipvmsX4Xbc4S67eN4seeVlkp7yAzk/Ul81pOL0VFrADXwJBAI/2Oq2AcSNOu6QY3JuzU4kN1mjKGDkBqmV3nHev9bp7NLyoasqzg8xo9lvuYjPpo47JXPgpH+CXXkLTTmqk/m8=";

        String publicCheckKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBO71iVLEu7umehJ0HJ5501wW1rSKTL3hkng+WRJZCnQ/3ZWLJrdLdgRRkaQMpzdF+AmqvtioluXjZdyrhLpkRtcAkjgQbBnRnL5zirJydmYZJU8CRSjrrER439hHTD9Zml1y9Pa//NPcfnd9iw6kZSX5rArEzFiKp3hRZGgecYwIDAQAB";

        PrivateKey privateKey = getPrivateRSAKey(privateCheckKey);

        PublicKey publicKey = getPublicRSAKey(publicCheckKey);

        System.out.println(publicKey);

        String encoded = "KO2ZO2rdw7vMM5kJi48U4qHqfwEGhpPjX84Qdq2nKx2+nkhDyegWQDhRbX1zhtawGoacQ1bMXwgcsAH5byoCec9MPNmmb24xCmRpFuR3CexRX6LREJwSGWEjkXf17t1EVjN6jcRLIIUeEVwmVW6xwGOTMvSo9qK5qfmkp7WRKRo=";

        System.out.println("After decryption:" + decryptToString(encoded, privateKey));

        String signature = "FIdfQHzBXvSFX1l1qbXCZwRUJ4vANVrEdbQqMuQPFTACzc7aXoUxWVf8QVoRngMb5RP2FbVpgyL+GVHnB7UKIcTFxXzmuLgHOZ6uuFzbKXaF9NZelnqzPADRplELN8rXj/s5YpUoSEx+0qWabkAYTBotgANn/EBg+ESnQAgD6So=";

        String dataToVerify = "965656";

        System.out.println("Verified signature = " + verify(dataToVerify, signature, publicKey, "SHA256withRSA"));

    }

    public static boolean verify(String data, String sign, PublicKey publicKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.decode(sign));
    }

    private static byte[] decrypt(byte[] text, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(NONE_PADDING, pro);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(text);
    }

    private static String decryptToString(byte[] text, Key key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return new String(decrypt(text, key));
    }

    public static String decryptToString(String text, Key key) throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        byte[] en = Base64.decode(text);
        return decryptToString(en, key);
    }

    public static PublicKey getPublicRSAKey(String key) throws InvalidKeySpecException {
        return bytesToPublicKey(org.bouncycastle.util.encoders.Base64.decode(key));
    }

    public static PrivateKey getPrivateRSAKey(String key) throws InvalidKeySpecException {
        return bytesToPrivateKey(org.bouncycastle.util.encoders.Base64.decode(key));
    }

    public static byte[] encrypt(byte[] content, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(NONE_PADDING, pro);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] decrypt(byte[] content, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(NONE_PADDING, pro);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PublicKey bytesToPublicKey(byte[] bytes) throws InvalidKeySpecException {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, pro);
            return kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            // Can't happen
        }
        return null;
    }

    private static PrivateKey bytesToPrivateKey(byte[] bytes) throws InvalidKeySpecException {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, pro);
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            //
        }
        return null;
    }

}
