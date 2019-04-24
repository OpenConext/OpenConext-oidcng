package oidc.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Document(collection = "authorization_codes")
public class AuthorizationCode {

    @Id
    private String id;

    private String code;

    private String userId;

    private String clientId;

    private List<String> scopes;

    private String redirectUri;

    public AuthorizationCode(String code, String userId, String clientId, List<String> scopes, String redirectUri) {
        this.code = code;
        this.userId = userId;
        this.clientId = clientId;
        this.scopes = scopes;
        this.redirectUri = redirectUri;
    }
}
