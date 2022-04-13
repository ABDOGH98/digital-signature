import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

public class Test1 {
    public static void main(String[] args) throws Exception {
        String data = "hello world" ;
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();

        byte[] dataByreFormat = data.getBytes(StandardCharsets.UTF_8);

        //****************************** Base64 && Base64URL Format *****************************************
        System.out.println("**********************Base64 && Base64URL Format********************************");

        String base64Format = cryptoUtil.encodeToBase64(dataByreFormat);
        String base64URLFormat = cryptoUtil.encodeToBase64URL(dataByreFormat);

        System.out.println("encode Base64URL Format => "+base64Format);
        System.out.println("encode Base64URL Format => "+base64URLFormat);

        byte[] decodeFromBase64 = cryptoUtil.decodeFromBase64(base64Format);
        System.out.println("decode Base64 Format => "+new String(decodeFromBase64));

        byte[] decodeFromBase64URL = cryptoUtil.decodeFromBase64URL(base64URLFormat);
        System.out.println("decode Base64URL Format => "+new String(decodeFromBase64URL));

        System.out.println("convert byte to Hex => "+cryptoUtil.encodeToHex(dataByreFormat));

        //****************************** AES Symetric Encryption *****************************************
        System.out.println("**********************AES Symetric Encryption********************************");

        SecretKey secretKey = cryptoUtil.generateSecretKey();

        String dataAESFormat = cryptoUtil.encryptAES(data.getBytes(), secretKey);
        System.out.println("data encrypt with AES => "+dataAESFormat);

        byte[] decryptAESByteFormat = cryptoUtil.decryptAES(dataAESFormat, secretKey);
        System.out.println("decrypt data AES => "+new String(decryptAESByteFormat));

    }
}
