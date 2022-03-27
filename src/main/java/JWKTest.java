import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class JWKTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, JOSEException, ParseException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

//        System.out.println(privateKey);
        System.out.println(publicKey);

        RSAKey jwk = new RSAKey.Builder((RSAPublicKey) publicKey)
                .privateKey((RSAPrivateKey) privateKey)
                .build();
        //System.out.println(jwk);

        RSAKey parsedJwk = RSAKey.parse("{\"p\":\"7_NJdfziBEfdb9TOItt0HkC6gHgdlBkQNTqM9Bba8tDbp0ol2Nrgd1UIYWQJZts87Uib8B0IPJTLrD7JPaiyiHf-_fBSPnUJi4AMD18DIjG_U6mseYW2MFxuwSJOVb5OXzetF4enny9dbN6KlA_YWukhZMXB7hn2YeNZHNShO-M\",\"kty\":\"RSA\",\"q\":\"4nBr29riStB90Z4ZXAAPWvkOQoUK79MK08s817lJZKzXql-eLppa0xpMEETpXI86_a8t20oQ_kcCfLEEGAgJ2CLaYNCq4gqxyZJU83y0CKmyircd8jzccP3nK0ll75ax2YsQSl44-hu5wWPP8xi3jHQYMwuThm5lbN6sVtNmMHk\",\"d\":\"Ot3WBcl8LUq64ppAHNRvbVQEGE1KMw28Jdwgm0gqcoFMvTgeikLs-0fqH5yGRIqSBXGgcYbE_YBKx2LPP1K66SMSKVITmTg-1sIlc5LEs4umAJnQ2qI6tNqFXoJ_l9-Kurd1TuGOi__AkaYR3450SC9MTbM40Vc4DEcIfWiVHmn3tdv7DaMqBPunZiclgj2wOEQVvyN6uYflpBpwegBtlfOl4Hp69Pi2k5SbrfmgnjKpqU_itfYMd4nbCfW4aCPHNW8u2n--40HIOUuKk47Ywxmu0z8fcfiisYEAesT7GftL7Aywr7fzxsr-HHafgTLr8KMdSMzVwrEYxzbYnIMB8Q\",\"e\":\"AQAB\",\"qi\":\"11tCJRkzXLxnM3Mo0UCMMe65gDOuZNeC6jHmbDjbwuGzTgMTJ1sQaFsLrVFXbOH-EpPh4eB5bTwOBQUTgRj991KQh8dre2lpBuAhAfamC9s6t_CkAqZA9UuJr2Nh2IGI6KxWQenDn_cF0COYmmAPJ5x_UMrnnarleY1fxUgjp0k\",\"dp\":\"j5EVJw9DfCQzjbHaFGkRtPgtnqg_qljEpdR-eZ0jK51jj1iCBJoRK9Uoyny8U1phvedvxd7ZCsZMhqaaadYB3D1PyEh-LPiB2YGntZq3mUICo-AlXiBuvcjQS6ZnEE5pPfdmDWoRFOGWGImeiLBiVyKd5FmeiwPlsvQAYYunXNk\",\"dq\":\"f46A0-qriyWDmu-KrY7DF6Yw6Dv1-z9RXBmi_oq702CiZLFUdEAzZbPsoUWQh7mPq5RhKqTAid0Kg59cBQWSNhT8G4mwmYEYwcoS3M6kxDSEBSw-TFUIgQYmkPXZ3GtxaHC0DpChXBL-QvitDe4gh5hmgWrGAfZyYC_XuVmAuVE\",\"n\":\"1D4mYw7bmsAwaRSkipd1x2daNfXPeOhtOkvjxJPY4oTpX--3P7F1XNan5krPoyv9zZp7nXWJOLu2QMeE4cMMhMDEq7ZTrPXKRUcVY6U_kHY2ZRco-dUerO_2NlVK43CqDPWtThtCD38Ork8sCNlk6z-t7x76ODHR05Ekx2JpFCXn9pyAwBhbGLfRv3_SBwHE05jSIc6sW1kBjuia_a_55ViPnogt7U4LPszHcCcmKybkY_WCwbW8ACjzp8ZFFWxNWvwiAZlraQ1kEnIxBrDgYbYW1romXu53MComqvXxAx-nvtGsYOTGSYnAIX4WxIujawOCqalfvQefKMVasOHeSw\"}\n");

        System.out.println(parsedJwk);
        System.out.println(parsedJwk.toRSAPublicKey());
//        System.out.println(jwk.toRSAPublicKey());
//        System.out.println(jwk.toRSAPrivateKey());
     }
}
