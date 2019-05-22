package oidc.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;
import java.util.Map;

@Document(collection = "web_keys")
public class WebKey {

    @Id
    private String id;

    private String keyId;

    private String jwk;

    private Date created;

}
