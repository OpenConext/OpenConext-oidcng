package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import oidc.model.AccessToken;
import oidc.model.OpenIDClient;
import oidc.model.RefreshToken;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.repository.RefreshTokenRepository;
import oidc.secure.TokenGenerator;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface OidcEndpoint {

    default Map<String, Object> tokenEndpointResponse(Optional<User> user, OpenIDClient client,
                                                      List<String> scopes) throws JOSEException {
        Map<String, Object> map = new HashMap<>();
        String accessTokenValue = getTokenGenerator().generateAccessToken();
        String sub = user.map(u -> u.getSub()).orElse(client.getClientId());
        getAccessTokenRepository().insert(new AccessToken(accessTokenValue, sub, client.getClientId(), scopes,
                accessTokenValidity(client)));
        map.put("access_token", accessTokenValue);
        if (client.getGrants().contains(GrantType.REFRESH_TOKEN.getValue())) {
            String refreshTokenValue = getTokenGenerator().generateRefreshToken();
            getRefreshTokenRepository().insert(new RefreshToken(refreshTokenValue, sub, client.getClientId(), scopes,
                    refreshTokenValidity(client), accessTokenValue));
            map.put("refresh_token", refreshTokenValue);
        }
        map.put("id_token", getTokenGenerator().generateIDTokenForTokenEndpoint(user, client.getClientId()));
        addSharedProperties(map, client);
        return map;
    }

    default Map<String, Object> authorizationEndpointResponse(User user, OpenIDClient client, Nonce nonce,
                                                              List<String> scopes, ResponseType responseType) throws JOSEException {
        Map<String, Object> map = new HashMap<>();
        String value = getTokenGenerator().generateAccessToken();
        if (AccessTokenHash.isRequiredInIDTokenClaims(responseType)) {
            getAccessTokenRepository().insert(new AccessToken(value, user.getSub(), client.getClientId(), scopes,
                    accessTokenValidity(client)));
            map.put("access_token", value);
        }
        String idToken = getTokenGenerator().generateIDTokenForAuthorizationEndpoint(user, client.getClientId(), nonce, responseType, value);
        map.put("id_token", idToken);
        addSharedProperties(map, client);
        return map;
    }

    default void addSharedProperties(Map<String, Object> map, OpenIDClient client) {
        map.put("token_type", "Bearer");
        map.put("expires_in", client.getAccessTokenValidity());
    }

    default Date accessTokenValidity(OpenIDClient client) {
        return tokenValidity(client.getAccessTokenValidity());
    }

    default Date refreshTokenValidity(OpenIDClient client) {
        return tokenValidity(client.getRefreshTokenValidity());
    }

    default Date tokenValidity(int validity) {
        LocalDateTime ldt = LocalDateTime.now().plusSeconds(validity);
        return Date.from(ldt.atZone(ZoneId.systemDefault()).toInstant());
    }

    TokenGenerator getTokenGenerator();

    AccessTokenRepository getAccessTokenRepository();

    RefreshTokenRepository getRefreshTokenRepository();
}
