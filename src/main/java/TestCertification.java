import java.security.PrivateKey;
import java.security.PublicKey;

public class TestCertification {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        PublicKey publicKey = cryptoUtil.publicKeyFromCertification("publicKey.cert");
        System.out.println("Public key *******************");
        System.out.println(cryptoUtil.encodeToBase64(publicKey.getEncoded()));
        PrivateKey privateKey = cryptoUtil.privateKeyFromCertification("myKey.jks","root123","myKey");
        System.out.println("private Key ****************");
        System.out.println(cryptoUtil.encodeToBase64(privateKey.getEncoded()));

    }
}
