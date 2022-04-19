import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class TestRsaDecrypt {
    public static void main(String[] args) throws Exception {

        String privateKeyBase64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJfiV/bUpFJHb6LJF2FlceOuP8VjT1ewmywgdO0udfOlBPLTSQWsGK+RezjNdFyWFDJIE64sGlmPFYxxuV09M/PE2Bp0/BJqsTUYC6MOAxvtrGqanFXt8LwkJ2qmwWtVa3B7rvxdsj6laJMyKJq2TFnVk+wU3daPLYxCHvUHc3l7AgMBAAECgYBVT4pPFzNRD9Txn3flegCVfUtOiLCJNaaDC5wBmQYhm0ADUJAEgpy/CL0os6Y3VwjzES8Utqr6QPc+kqYma/kgg9AlUoO/59pD6Kjh+CVurv6TmX9mnlTTK5Ub/HGHPX7i3g628WJmJfzLcTBaUCJmS9OiEePsetJwjJ3tkxNKcQJBAOcj2YD+VcW9a+JEW8wPxSKCmya/KZwr0kfOhh/o3WkQTVfu99dWfoQREOL16vVcJ9bQqsAf/GQ2T23zlXl3nYMCQQCoOEhq5dFQ0r14s9YYP7iK03IqSTPfsT/0MvPGJEUFCVRia2HRaIsAqAZKeGwVY1gOJXzH6gf+D74To6m1tyqpAkEAh035GQXJeAO2j7GsevwQTm9eG4Rz+zO72MUQxsUuNz6PyBXfh3LehLjoxbNnY1IbECj+i5Et0gvo21hn+78FuQJAJT8pEbpHKX0wBLzVB9N8GgkNez1wJfSKM5jgjxvSyHWzYINkSki6lm+dzPly/R1dDuzP/zfbgy6bKKARYLHo2QJAYkNBCS9L7hMZN1qqKlVBatLu3DSVU5+I4/zMG9enkH9C9l50dPtiR1styz84k43qDyXlM7rrGqQfkKljp+j2Uw==";
        String messageEncypted = "S8pIDN82Pdb/+hu3tWwbCyPX/M25hCwlRdTCkEMEIAC/lvDxzU/JDz/nmyO5MrElojtZdbUmVO/YZRK9TNaMM65btE0pIDvA/oA6MqyrWkB0KUZTyXeZoeDQIiUhHDeL7Ze/Y31a/Hmlx466epaxuFOPXc5XDOJX3DVFkKkzlRc=";
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        byte[] decode = Base64.getDecoder().decode(privateKeyBase64);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decode));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(messageEncypted));
        System.out.println(new String(decryptedBytes));
    }
}
