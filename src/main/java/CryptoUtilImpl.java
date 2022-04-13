import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
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

}
