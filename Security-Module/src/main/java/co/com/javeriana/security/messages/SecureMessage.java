package co.com.javeriana.security.messages;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * Created by garciniegas on 18/10/2015.
 
 cambio por defecto 1100 final
 cambio por defecto 1100 final - ESTE CAMBIO
 DEBE SER MANEJADO POR MERGER ESTRATEGICO
 
 $esta es una linea que estorva por conflictos
 */

@XmlRootElement(namespace = "http://javeriana.com/aes/secutiry/1.0.0")
public class SecureMessage {

    private String id;
    private byte[] signature;
    private byte[] content;
    private byte[] key;

	/* constructo por default **/
    public SecureMessage() {
    }

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }
}
