package oidc.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.mongodb.core.mapping.Document;

import java.nio.charset.Charset;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@NoArgsConstructor
@Document(collection = "refresh_tokens")
@Getter
public class RefreshToken extends AccessToken {

    private String accessTokenId;

    public RefreshToken(AccessToken accessToken, String refreshTokenValue, Date expiresIn) {
        super(refreshTokenValue, accessToken.getSub(), accessToken.getClientId(), accessToken.getScopes(),
                accessToken.getSigningKeyId(), expiresIn, accessToken.isClientCredentials(), null,
                accessToken.getUnspecifiedUrnHash());
        this.accessTokenId = accessToken.getId();
    }

}

