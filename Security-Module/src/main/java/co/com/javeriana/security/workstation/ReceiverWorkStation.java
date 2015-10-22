package co.com.javeriana.security.workstation;

import co.com.javeriana.security.messages.SecureMessage;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by garciniegas on 18/10/2015.
 */

public class ReceiverWorkStation extends AbstractWorkStation{

    // -------------------------------------------

    public void receiveSecureFile() throws Exception{

        String outputFile          = "C:/security/message_out/secure_message.xml";
        PublicKey remotePublicKey  = keyBuilderProcessor.restorePublicKey("JennyPublicKey.key");
        PrivateKey localPrivateKey = keyBuilderProcessor.restorePrivateKey("AlejoPrivateKey.key");
        SecureMessage sm           = parser.readMessage(outputFile);

        byte[] symmetricKeyData = cipher.decryptKey(sm.getKey(), localPrivateKey);
        Key symmetricKey        = keyBuilderProcessor.restoreSymmetricKey(symmetricKeyData) ;

        byte[] textPlain       = cipher.decryptText( sm.getContent(),symmetricKey );
        boolean validSignature = signer.verifySignature( sm.getSignature(),textPlain, remotePublicKey);

        System.out.println( "------------------ MESSAGE RECEIVED ------------------" );
        System.out.println( "ID     : " + sm.getId() );
        System.out.println( "CONTENT: " + new String( textPlain ) );
        System.out.println( "VERIFIED SIGNATURE: " + validSignature);

    }

    // -------------------------------------------

    public static void main( String[] arts ) throws Exception {

        ReceiverWorkStation ws = new ReceiverWorkStation();
        ws.receiveSecureFile();

    }

}
