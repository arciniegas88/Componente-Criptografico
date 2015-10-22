package co.com.javeriana.security.workstation;

import co.com.javeriana.security.messages.MessageParser;
import co.com.javeriana.security.tools.CipherArtifact;
import co.com.javeriana.security.tools.KeyBuilderProcessor;
import co.com.javeriana.security.tools.SignatureArtifact;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Created by garciniegas on 19/10/2015.
 */
public abstract class AbstractWorkStation {

    protected KeyBuilderProcessor keyBuilderProcessor = new KeyBuilderProcessor();
    protected MessageParser parser = new MessageParser();
    protected CipherArtifact cipher = new CipherArtifact();
    protected SignatureArtifact signer = new SignatureArtifact();

    public AbstractWorkStation() {
    }

    protected byte[] readInputMessage( String file )throws IOException {

        File filePublicKey = new File( file );
        FileInputStream fis = new FileInputStream( file );
        byte[] data = new byte[(int) filePublicKey.length()];
        fis.read(data);
        fis.close();

        return data;
    }

}
