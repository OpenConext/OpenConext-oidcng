package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import oidc.model.AccessToken;
import oidc.model.OpenIDClient;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.secure.TokenGenerator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface OidcEndpoint {

    default Map<String, Object> tokenEndpointResponse(Optional<User> user, OpenIDClient client,
                                                      List<String> scopes) throws JOSEException {
        Map<String, Object> map = new HashMap<>();
        String value = getTokenGenerator().generateAccessToken();
        String sub = user.map(u -> u.getSub()).orElse(client.getClientId());
        getAccessTokenRepository().insert(new AccessToken(value, sub, client.getClientId(), scopes));
        map.put("access_token", value);
        map.put("id_token", getTokenGenerator().generateIDTokenForTokenEndpoint(user, client.getClientId()));
        addSharedProperties(map);
        return map;
    }

    default Map<String, Object> authorizationEndpointResponse(User user, OpenIDClient client, Nonce nonce,
                                                              List<String> scopes, ResponseType responseType) throws JOSEException {
        Map<String, Object> map = new HashMap<>();
        String value = getTokenGenerator().generateAccessToken();
        if (AccessTokenHash.isRequiredInIDTokenClaims(responseType)) {
            getAccessTokenRepository().insert(new AccessToken(value, user.getSub(), client.getClientId(), scopes));
            map.put("access_token", value);
        }
        String idToken = getTokenGenerator().generateIDTokenForAuthorizationEndpoint(user, client.getClientId(), nonce, responseType, value);
        map.put("id_token", idToken);
        addSharedProperties(map);
        return map;
    }

    default void addSharedProperties(Map<String, Object> map) {
        map.put("token_type", "Bearer");
        map.put("expires_in", 5 * 60);
    }

    TokenGenerator getTokenGenerator();

    AccessTokenRepository getAccessTokenRepository();
}
