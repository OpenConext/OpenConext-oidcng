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

    private String sub;

    private String clientId;

    private List<String> scopes;

    private String redirectUri;

    private String codeChallenge;

    private String codeChallengeMethod;

    public AuthorizationCode(String code, String sub, String clientId, List<String> scopes, String redirectUri) {
        this(code, sub, clientId, scopes, redirectUri, null, null);
    }

    public AuthorizationCode(String code, String sub, String clientId, List<String> scopes, String redirectUri, String codeChallenge, String codeChallengeMethod) {
        this.code = code;
        this.sub = sub;
        this.clientId = clientId;
        this.scopes = scopes;
        this.redirectUri = redirectUri;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
    }
}
