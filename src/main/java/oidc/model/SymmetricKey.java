package oidc.model;

import lombok.Getter;
import org.apache.commons.codec.binary.Base64;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.util.Assert;

import java.util.Date;

@Getter
@Document(collection = "symmetric_keys")
public class SymmetricKey {

    @Transient
    public static final String PRIMARY_KEY = "primary";

    @Id
    private String id;

    private String keyId;

    private String aead;

    private Date created;

    public SymmetricKey(String keyId, String aead, Date created) {
        Assert.notNull(keyId, "KeyID must not be null");
        Assert.notNull(aead, "Aead must not be null");
        Assert.isTrue(Base64.isBase64(aead),"Aead must be base64 encoded");
        this.keyId = keyId;
        this.aead = aead;
        this.created = created;
    }

}
