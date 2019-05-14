package oidc.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
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

    private Date expiresIn;

    public AuthorizationCode(String code, String sub, String clientId, List<String> scopes, String redirectUri,
                             String codeChallenge, String codeChallengeMethod, List<String> idTokenClaims,
                             Date expiresIn) {
        this.code = code;
        this.sub = sub;
        this.clientId = clientId;
        this.scopes = scopes;
        this.redirectUri = redirectUri;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.idTokenClaims = idTokenClaims;
        this.expiresIn = expiresIn != null ? expiresIn :
                Date.from(LocalDateTime.now().plusMinutes(5).atZone(ZoneId.systemDefault()).toInstant());
    }

    @Transient
    public boolean isExpired(Clock clock) {
        return clock.instant().isAfter(expiresIn.toInstant());
    }

}
