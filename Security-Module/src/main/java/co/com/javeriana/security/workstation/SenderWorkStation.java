package co.com.javeriana.security.workstation;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by garciniegas on 18/10/2015.
 */

public class SenderWorkStation extends AbstractWorkStation{

    // -------------------------------------------

    public void sendSecureFile()throws Exception{

        String inputFile            = "C:/security/message_in/input.txt";
        String outputFile           = "C:/security/message_out/secure_message.xml";
        PrivateKey localPrivateKey  = keyBuilderProcessor.restorePrivateKey("JennyPrivateKey.key");
        PublicKey externalPublicKey = keyBuilderProcessor.restorePublicKey("AlejoPublicKey.key");

        byte[] textPlainData = readInputMessage( inputFile );

        //digital signature -----------------

        signer.init(textPlainData);

        byte[] messageDigest = signer.calculateMessageDigest();
        byte[] signature     = signer.applySignature(messageDigest, localPrivateKey);

        //content cipher ---------------------

        Key symmetricKey       = keyBuilderProcessor.buildSymmetricKey();
        byte[]cipherContent    = cipher.encryptText( textPlainData,symmetricKey );
        byte[]keyCipherContent = cipher.encryptKey( symmetricKey.getEncoded(),externalPublicKey );


        //write secure message ----------------

        parser.generateMessage( signature,cipherContent,keyCipherContent,outputFile );
        System.out.println("------------------ MESSAGE SENT ------------------");
    }

    // -------------------------------------------

    public static void main( String[] arts ) throws Exception {

        SenderWorkStation ws = new SenderWorkStation();
        ws.sendSecureFile();
    }

}
