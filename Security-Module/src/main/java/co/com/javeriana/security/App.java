package co.com.javeriana.security;

import co.com.javeriana.security.tools.KeyBuilderProcessor;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Hello world!
 */
public class App {

    public static void main(String[] args) throws Exception {

        KeyBuilderProcessor p = new KeyBuilderProcessor();
        p.build("AlejoPrivateKey.key","AlejoPublicKey.key");
        p.build("JennyPrivateKey.key","JennyPublicKey.key");

        //symmetricService( readInputMessage( "C:/security/message_in/input.txt" ) );
    }

    protected static byte[] readInputMessage( String file )throws IOException {

        File filePublicKey = new File( file );
        FileInputStream fis = new FileInputStream( file );
        byte[] data = new byte[(int) filePublicKey.length()];
        fis.read(data);
        fis.close();

        return data;
    }


    public static void symmetricService(byte[] plainText) throws Exception {

        // get a DES private key
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        Key key = keyGen.generateKey();

        // get a DES cipher object and print the provider
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(plainText);
        System.out.println(new String(cipherText, "UTF8"));

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] newPlainText = cipher.doFinal(cipherText);
        System.out.println( newPlainText );
    }

    public static void digest(String message) throws Exception {

        byte[] plainText = message.getBytes("UTF8");

        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(plainText);
        System.out.println("\nDigest: ");
        System.out.println(new String(messageDigest.digest(), "UTF8"));

    }

    public static void asymmetricService(String message) throws Exception {

        byte[] plainText = message.getBytes("UTF8");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair key = keyGen.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        cipher.init(Cipher.ENCRYPT_MODE, key.getPublic());
        byte[] cipherText = cipher.doFinal(plainText);
        System.out.println(new String(cipherText, "UTF8"));

        cipher.init(Cipher.DECRYPT_MODE, key.getPrivate());
        byte[] newPlainText = cipher.doFinal(cipherText);
        System.out.println(new String(newPlainText, "UTF8"));

    }

    public static void generatePairKey() throws Exception {



    }

    public static void digitalSignature(String message) throws Exception {

        byte[] plainText = message.getBytes("UTF8");
        //
        // get an MD5 message digest object and compute the plaintext digest
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(plainText);
        byte[] md = messageDigest.digest();

        System.out.println("\nDigest: ");
        System.out.println(new String(md, "UTF8"));


        File filePublicKey = new File("C:/bea/publicKey.key");
        FileInputStream fis = new FileInputStream("C:/bea/publicKey.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        // Read Private Key.
        File filePrivateKey = new File("C:/bea/privateKey.key");
        fis = new FileInputStream("C:/bea/privateKey.key");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));

        //
        // get an RSA cipher and list the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        //
        // encrypt the message digest with the RSA private key
        // to create the signature
        System.out.println("\nStart encryption");

        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] cipherText = cipher.doFinal(md);
        System.out.println("Finish encryption: ");
        System.out.println(new String(cipherText, "UTF8"));

        //
        // to verify, start by decrypting the signature with the
        // RSA private key
        System.out.println("\nStart decryption");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] newMD = cipher.doFinal(cipherText);
        System.out.println("Finish decryption: ");
        System.out.println(new String(newMD, "UTF8"));
        //
        // then, recreate the message digest from the plaintext
        // to simulate what a recipient must do
        System.out.println("\nStart signature verification");
        messageDigest.reset();
        messageDigest.update(plainText);
        byte[] oldMD = messageDigest.digest();
        //
        // verify that the two message digests match
        int len = newMD.length;
        if (len > oldMD.length) {
            System.out.println("Signature failed, length error");
            System.exit(1);
        }
        for (int i = 0; i < len; ++i)
            if (oldMD[i] != newMD[i]) {
                System.out.println("Signature failed, element error");
                System.exit(1);
            }
        System.out.println("Signature verified");

    }


}
