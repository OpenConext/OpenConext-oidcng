package oidc.model;

import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.mapping.Document;

import java.nio.charset.Charset;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@NoArgsConstructor
@Document(collection = "refresh_tokens")
public class RefreshToken extends AccessToken {

    private String accessTokenValue;

    public RefreshToken(String value, String sub, String clientId, List<String> scopes, Date expiresIn, String accessTokenValue, boolean clientCredentials) {
        super(value, sub, clientId, scopes, expiresIn, clientCredentials);
        this.accessTokenValue = accessTokenValue;
    }

    public String getAccessTokenValue() {
        return accessTokenValue;
    }
}

