package oidc.model;

import lombok.Getter;
import org.apache.commons.codec.binary.Base64;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.util.Assert;

import java.util.Date;

@Getter
@Document(collection = "signing_keys")
public class SigningKey {

    @Id
    private String id;

    private String keyId;

    private String symmetricKeyId;

    private String jwk;

    private Date created;

    public SigningKey(String keyId, String symmetricKeyId, String jwk, Date created) {
        Assert.notNull(keyId, "KeyID must not be null");
        Assert.notNull(symmetricKeyId, "SymmetricKeyId must not be null");
        Assert.notNull(jwk, "Jwk must not be null");
        Assert.isTrue(Base64.isBase64(jwk), "Jwk must be base64 encoded");
        this.keyId = keyId;
        this.symmetricKeyId = symmetricKeyId;
        this.jwk = jwk;
        this.created = created;
    }
}
