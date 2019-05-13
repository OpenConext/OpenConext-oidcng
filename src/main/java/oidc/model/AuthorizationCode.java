package oidc.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@NoArgsConstructor
@Getter
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

    private List<String> idTokenClaims;

    public AuthorizationCode(String code, String sub, String clientId, List<String> scopes, String redirectUri,
                             String codeChallenge, String codeChallengeMethod, List<String> idTokenClaims) {
        this.code = code;
        this.sub = sub;
        this.clientId = clientId;
        this.scopes = scopes;
        this.redirectUri = redirectUri;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.idTokenClaims = idTokenClaims;
    }
}
