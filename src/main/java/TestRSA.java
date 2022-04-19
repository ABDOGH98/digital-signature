import javax.crypto.Cipher;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class TestRSA {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        KeyPair keyPair = cryptoUtil.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println("*********** Private Key **************");
        System.out.println(Arrays.toString(privateKey.getEncoded()));
        System.out.println("*********** Public Key **************");
        System.out.println(Arrays.toString(publicKey.getEncoded()));
        System.out.println("\n*********** Private Key Base64 **************\n");
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("\n*********** Public Key Base64 **************\n");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        String message = "Hello ziza";

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] messageEncryptedBytes = cipher.doFinal(message.getBytes());

        System.out.println("\n*********** Plain Text **************\n");
        System.out.println(message);
        System.out.println("\n*********** Encrypted Message Bytes Format **************\n");
        System.out.println(Arrays.toString(messageEncryptedBytes));
        System.out.println("\n*********** Encrypted Message Base64 Format **************\n");
        System.out.println(Base64.getEncoder().encodeToString(messageEncryptedBytes));


    }
}
