package co.com.javeriana.security.tools;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by garciniegas on 18/10/2015.
 */
public class KeyBuilderProcessor {

    // -------------------------------------------

    public static final String SYMMETRIC_ALGORITHM  = "DES";
    public static final String ASYMMETRIC_ALGORITHM = "RSA";
    public static final String BASE_STORE_PATH = "C:/security/";


    public Key restoreSymmetricKey( byte[] symmetricKeyData )throws DecoderException{

        String keyLine = new String( symmetricKeyData );
        byte[] encoded = Hex.decodeHex( keyLine.toCharArray() );
        SecretKey key = new SecretKeySpec(encoded, SYMMETRIC_ALGORITHM);

        return key;
    }
    // build de symmetric key -----------------

    public Key buildSymmetricKey() throws NoSuchAlgorithmException,IOException{

        KeyGenerator symmetricKeyGen = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        symmetricKeyGen.init(56);
        Key key = symmetricKeyGen.generateKey();

        return key;
    }


    // -------------------------------------------

    public void build( String privateKeyName, String publicKeyName )throws NoSuchAlgorithmException,IOException{

        // build asymmetric keys -----------------

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance( ASYMMETRIC_ALGORITHM );
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        FileOutputStream fos = new FileOutputStream(new File(BASE_STORE_PATH + publicKeyName));
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        fos = new FileOutputStream(new File(BASE_STORE_PATH + privateKeyName));
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

    // -------------------------------------------

    public PrivateKey restorePrivateKey( String privateKeyName )throws NoSuchAlgorithmException,InvalidKeySpecException, IOException{

        File filePrivateKey = new File( BASE_STORE_PATH + privateKeyName );
        FileInputStream fis = new FileInputStream( BASE_STORE_PATH + privateKeyName );
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance(ASYMMETRIC_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
        return privateKey;
    }


    // -------------------------------------------

    public PublicKey restorePublicKey( String publicKeyName )throws NoSuchAlgorithmException,InvalidKeySpecException, IOException{

        File filePublicKey = new File( BASE_STORE_PATH + publicKeyName );
        FileInputStream fis = new FileInputStream( BASE_STORE_PATH + publicKeyName );
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance(ASYMMETRIC_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
        return publicKey;
    }

}
