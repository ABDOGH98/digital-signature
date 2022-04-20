import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class CryptoUtilImpl {

    //****************************** Base64 && Base64URL Format *****************************************

    public String encodeToBase64(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }
    public byte[] decodeFromBase64(String dataBase64){
        return Base64.getDecoder().decode(dataBase64.getBytes());
    }
    public String encodeToBase64URL(byte[] data){
        return Base64.getUrlEncoder().encodeToString(data);
    }
    public byte[] decodeFromBase64URL(String dataBase64){
        return Base64.getUrlDecoder().decode(dataBase64.getBytes());
    }

    public String encodeToHex(byte[] data){
        return DatatypeConverter.printHexBinary(data);
    }

    //****************************** AES Symetric Encryption *****************************************

    public SecretKey generateSecretKey()throws Exception{
        KeyGenerator keyGenerator=KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public SecretKey generateSecretKey(String secret)throws Exception{
        SecretKey secretKey=new SecretKeySpec(secret.getBytes(),0,secret.length(),"AES");
        return secretKey;
    }

    public String encryptAES(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] encryptedData = cipher.doFinal(data);
        String encodedEncryptedData = Base64.getEncoder().encodeToString(encryptedData);
        return encodedEncryptedData;
    }

    public byte[] decryptAES(String encodedEncryptedData, SecretKey secretKey) throws Exception {
        byte[] decodeEcryptedData = Base64.getDecoder().decode(encodedEncryptedData);
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        byte[] decryptedBytes = cipher.doFinal(decodeEcryptedData);
        return decryptedBytes;
    }

    //****************************** RSA Asymetric Encryption *****************************************

    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }
    public PublicKey publicKey(String pkBase64) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decode = Base64.getDecoder().decode(pkBase64);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decode));
        return publicKey;
    }

    public PrivateKey privateKey(String pkBase64) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decode = Base64.getDecoder().decode(pkBase64);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decode));
        return privateKey;
    }

    public String encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] bytes = cipher.doFinal(data);
        return encodeToBase64(bytes);
    }

    public String decryptRSA(String dataBase64, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(dataBase64));
        return new String(bytes);
    }

    public PublicKey publicKeyFromCertification(String filename) throws Exception {
        FileInputStream inputStream = new FileInputStream(filename);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(inputStream);
        System.out.println(certificate.toString());
        return certificate.getPublicKey();
    }
    public PrivateKey privateKeyFromCertification(String filename,String password, String alias) throws Exception {
        FileInputStream inputStream = new FileInputStream(filename);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(inputStream,password.toCharArray());
        Key key = keyStore.getKey(alias, password.toCharArray());
        PrivateKey privateKey = (PrivateKey)key ;
        return privateKey;
    }

}
