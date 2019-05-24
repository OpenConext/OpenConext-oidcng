package oidc.model;

import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Getter
@Document(collection = "signing_keys")
public class SigningKey {

    @Id
    private String id;

    private String keyId;

    private String jwk;

    private Date created;

    public SigningKey(String keyId, String jwk, Date created) {
        this.keyId = keyId;
        this.jwk = jwk;
        this.created = created;
    }
}
