package co.com.javeriana.security.messages;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.UUID;

/**  este es otro cambio
 * Created by garciniegas on 18/10/2015.
 */
 
 
 
public class MessageParser {

    //  aqui hay un nuevo cambio-------------------------------------------

    public void generateMessage( byte[] signature, byte[] content, byte[]keyCipherContent, String target ) throws JAXBException, UnsupportedEncodingException {

        JAXBContext ctx = JAXBContext.newInstance( SecureMessage.class );
        Marshaller m = ctx.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        SecureMessage sm = new SecureMessage();
        sm.setContent(content);
        sm.setKey( keyCipherContent );
        sm.setSignature(signature);
        sm.setId(UUID.randomUUID().toString());

        m.marshal( sm,new File(target));
    }


    // -------------------------------------------

    public SecureMessage readMessage( String path ) throws JAXBException, UnsupportedEncodingException {

        JAXBContext ctx = JAXBContext.newInstance(SecureMessage.class);
        Unmarshaller um = ctx.createUnmarshaller();
        SecureMessage sm = (SecureMessage) um.unmarshal( new File(path) );

        return sm;
    }

}
