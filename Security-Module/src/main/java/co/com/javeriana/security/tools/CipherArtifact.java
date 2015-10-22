package co.com.javeriana.security.tools;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * Created by garciniegas on 18/10/2015.
 */

public class CipherArtifact {

    public static final String KEY_CIPHER_ALGORITHM     = "RSA/ECB/PKCS1Padding";
    public static final String CONTENT_CIPHER_ALGORITHM = "DES/ECB/PKCS5Padding";

    public byte[] encryptKey( byte[] targetKeyContent, Key key ) throws NoSuchAlgorithmException, NoSuchPaddingException,
                                                                        InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        char[] hex = Hex.encodeHex(targetKeyContent);
        String data = String.valueOf(hex);

        Cipher cipher = Cipher.getInstance( KEY_CIPHER_ALGORITHM );
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherKeyText = cipher.doFinal( data.getBytes() );

        return cipherKeyText;
    }


    public byte[] decryptKey( byte[] sourceKey, Key key ) throws NoSuchAlgorithmException, NoSuchPaddingException,
                                                                 InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance( KEY_CIPHER_ALGORITHM );
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] newSourceKey = cipher.doFinal(sourceKey);

        return newSourceKey;
    }

    public byte[] encryptText( byte[] textPlain, Key key ) throws NoSuchAlgorithmException, NoSuchPaddingException,
                                                                             InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance( CONTENT_CIPHER_ALGORITHM );
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(textPlain);

        return cipherText;
    }

    public byte[] decryptText( byte[] cipherText, Key key ) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance( CONTENT_CIPHER_ALGORITHM );
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] newPlainText = cipher.doFinal(cipherText);

        return newPlainText;
    }

}
