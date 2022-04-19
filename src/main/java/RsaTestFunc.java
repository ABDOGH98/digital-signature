import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RsaTestFunc {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        KeyPair keyPair = cryptoUtil.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String data = "Hello abdo how are u";

        String encryptData = cryptoUtil.encryptRSA(data.getBytes(), publicKey);
        System.out.println("************ Encrypted Data ************\n");
        System.out.println(encryptData);
        System.out.println("\n************ Decrypted Data ************\n");
        String decryptData = cryptoUtil.decryptRSA(encryptData, privateKey);
        System.out.println(decryptData);
    }
}
