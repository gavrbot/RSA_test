import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSABase64Test {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        System.out.println(privateKey);
        System.out.println(publicKey);

        byte[] encodedPrivateKey = privateKey.getEncoded();
        byte[] encodedPublicKey = publicKey.getEncoded();


        String b64PrivateKey = Base64.getEncoder().encodeToString(encodedPrivateKey);
        String b64PublicKey = Base64.getEncoder().encodeToString(encodedPublicKey);


        System.out.println(b64PrivateKey);
        System.out.println(b64PublicKey);


        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64PrivateKey));
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(b64PublicKey));
        PublicKey pubKey = kf.generatePublic(keySpecX509);

        System.out.println(privKey);
        System.out.println(pubKey);

        String checkKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlOJu6TyygqxfWT7eLtGDwajtN" +
                "FOb9I5XRb6khyfD1Yt3YiCgQWMNW649887VGJiGr/L5i2osbl8C9+WJTeucF+S76" +
                "xFxdU6jE0NQ+Z+zEdhUTooNRaY5nZiu5PgDB0ED/ZKBUSLKL7eibMxZtMlUDHjm4" +
                "gwQco1KRMDSmXSMkDwIDAQAB";

        X509EncodedKeySpec keySpecX509Check = new X509EncodedKeySpec(Base64.getDecoder().decode(checkKey));
        PublicKey pubKeyCheck = kf.generatePublic(keySpecX509Check);

        System.out.println(pubKeyCheck);
    }
}
