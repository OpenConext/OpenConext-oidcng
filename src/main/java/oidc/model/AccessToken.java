package oidc.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;
import java.util.List;

@NoArgsConstructor
@Getter
@Document(collection = "access_tokens")
public class AccessToken {

    @Id
    private String id;

    private String value;

    private String sub;

    private String clientId;

    private List<String> scopes;

    private Date expiresIn;

    public AccessToken(String value, String sub, String clientId, List<String> scopes, Date expiresIn) {
        this.value = value;
        this.sub = sub;
        this.clientId = clientId;
        this.scopes = scopes;
        this.expiresIn = expiresIn;
    }

}
