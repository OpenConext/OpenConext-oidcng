package oidc.model;

import lombok.NoArgsConstructor;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;
import java.util.List;

@NoArgsConstructor
@Document(collection = "refresh_tokens")
public class RefreshToken extends AccessToken {

    private String accessTokenValue;

    public RefreshToken(String jwtId, String value, String sub, String clientId, List<String> scopes, String signingKeyId, Date expiresIn,
                        String accessTokenValue, boolean clientCredentials, String unspecifiedUrnHash) {
        super(jwtId, value, sub, clientId, scopes, signingKeyId, expiresIn, clientCredentials, null, unspecifiedUrnHash);
        this.accessTokenValue = accessTokenValue;
    }

    public String getAccessTokenValue() {
        return accessTokenValue;
    }
}

