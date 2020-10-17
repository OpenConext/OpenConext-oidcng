package oidc;

import oidc.model.AccessToken;
import oidc.model.RefreshToken;
import oidc.model.User;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static java.util.Collections.singletonList;

public interface SeedUtils {

    default AccessToken accessToken(String value, Date expiresIn) {
        return new AccessToken(value, "sub", "clientId", singletonList("openid"), "K0000001", expiresIn, false, null, null);
    }

    default AccessToken accessToken(String value, String signingKey) {
        return new AccessToken(value, "sub", "clientId", singletonList("openid"), signingKey, new Date(), false, null, null);
    }

    default AccessToken accessToken(String unspecifiedUrnHash) {
        return new AccessToken(UUID.randomUUID().toString(), "sub", "clientId", singletonList("openid"),
                "K0000001", new Date(), false, null, unspecifiedUrnHash);
    }

    default RefreshToken refreshToken(String signingKey) {
        return new RefreshToken(accessToken("value", signingKey), UUID.randomUUID().toString(), new Date());
    }

    default RefreshToken refreshToken(Date expiresIn) {
        return new RefreshToken(accessToken("value", "signingKey"), UUID.randomUUID().toString(), expiresIn);
    }

    default RefreshToken refreshTokenWithValue(String value) {
        return new RefreshToken(accessToken("value", "signingKey"), value, new Date());
    }

    default User user(String key) {
        return new User("sub", "unspecifiedNameId",
                "authenticatingAuthority", "clientId",
                attributes(key), Collections.singletonList("acr"));
    }

    default Map<String, Object> attributes(String key) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(key, Collections.singletonList("value"));
        return attributes;
    }


}
