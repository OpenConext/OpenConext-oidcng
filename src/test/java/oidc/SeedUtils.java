package oidc;

import oidc.model.AccessToken;
import oidc.model.RefreshToken;
import oidc.model.User;

import java.util.*;

import static java.util.Collections.singletonList;

public interface SeedUtils {

    default AccessToken accessToken(String jwtId, Date expiresIn) {
        return new AccessToken(jwtId, "sub", "clientId", singletonList("openid"), "K0000001", expiresIn, false, null, null);
    }

    default AccessToken accessToken(String jwtId, String signingKey) {
        return new AccessToken(jwtId, "sub", "clientId", singletonList("openid"), signingKey, new Date(), false, null, null);
    }

    default AccessToken accessToken(String unspecifiedUrnHash) {
        return new AccessToken(UUID.randomUUID().toString(), "sub", "clientId", singletonList("openid"),
                "K0000001", new Date(), false, null, unspecifiedUrnHash);
    }

    default RefreshToken refreshToken(String signingKey) {
        return new RefreshToken(UUID.randomUUID().toString(), accessToken(UUID.randomUUID().toString(), signingKey), new Date());
    }

    default RefreshToken refreshToken(Date expiresIn) {
        return new RefreshToken(UUID.randomUUID().toString(), accessToken(UUID.randomUUID().toString(), "signingKey"), expiresIn);
    }

    default RefreshToken refreshTokenWithValue(String jwtId) {
        return new RefreshToken(jwtId, accessToken(jwtId, "signingKey"), new Date());
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
