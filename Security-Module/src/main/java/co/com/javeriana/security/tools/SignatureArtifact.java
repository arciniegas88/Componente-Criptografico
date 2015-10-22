package co.com.javeriana.security.tools;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;


/**
 * Created by garciniegas on 18/10/2015.
 */

public class SignatureArtifact {

    private static final String DIGEST_ALGORITHM = "MD5";
    private static final String SIGNATURE_ALGORITHM = "RSA/ECB/PKCS1Padding";

    private byte[] message;

    public void init(byte[] message) {
        this.message = message;
    }

    // -------------------------------

    public byte[] calculateMessageDigest() throws NoSuchAlgorithmException {

        MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGORITHM);
        messageDigest.update(message);
        byte[] md = messageDigest.digest();

        return md;
    }

    // -------------------------------

    public byte[] applySignature(byte[] messageDigest, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(SIGNATURE_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] cipherText = cipher.doFinal(messageDigest);

        return cipherText;
    }


    // -------------------------------

    public boolean verifySignature(byte[] signature, byte[] plainText,
                                   PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(SIGNATURE_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] trustedMD = cipher.doFinal(signature);

        MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGORITHM);
        messageDigest.update(plainText);
        byte[] evaluatedMD = messageDigest.digest();

        int len = evaluatedMD.length;

        if (len > trustedMD.length) {
            System.out.println("Invalid signature, different lengths");
            return false;
        }

        for (int i = 0; i < len; ++i) {
            if (evaluatedMD[i] != trustedMD[i]) {
                System.out.println("Invalid signature, different content");
                return false;
            }
        }

        return true;
    }


}
