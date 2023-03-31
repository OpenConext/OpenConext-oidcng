package oidc.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@NoArgsConstructor
@Document(collection = "refresh_tokens")
@Getter
public class RefreshToken extends AccessToken {

    //Backward compatibility
    private String accessTokenValue;
    private String innerValue;

    private String accessTokenId;

    public RefreshToken(String jwtId, AccessToken accessToken, Date expiresIn) {
        super(jwtId, accessToken.getSub(), accessToken.getClientId(), accessToken.getScopes(),
                accessToken.getSigningKeyId(), expiresIn, accessToken.isClientCredentials(), null,
                accessToken.getUnspecifiedUrnHash());
        this.accessTokenId = accessToken.getId();
    }

    public String getAccessTokenValue() {
        return accessTokenValue;
    }

    public String getInnerValue() {
        return innerValue;
    }
}

