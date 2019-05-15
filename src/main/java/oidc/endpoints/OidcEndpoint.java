package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
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
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public interface OidcEndpoint {

    default Map<String, Object> tokenEndpointResponse(Optional<User> user, OpenIDClient client,
                                                      List<String> scopes, List<String> idTokenClaims, boolean clientCredentials) throws JOSEException {
        Map<String, Object> map = new HashMap<>();
        TokenGenerator tokenGenerator = getTokenGenerator();
        String accessTokenValue = user.map(u -> tokenGenerator.generateAccessTokenWithEmbeddedUserInfo(u, client, scopes)).orElse(tokenGenerator.generateAccessToken());
        String sub = user.map(User::getSub).orElse(client.getClientId());

        getAccessTokenRepository().insert(new AccessToken(accessTokenValue, sub, client.getClientId(), scopes,
                accessTokenValidity(client), !user.isPresent()));
        map.put("access_token", accessTokenValue);

        if (client.getGrants().contains(GrantType.REFRESH_TOKEN.getValue())) {
            String refreshTokenValue = tokenGenerator.generateRefreshToken();
            getRefreshTokenRepository().insert(new RefreshToken(refreshTokenValue, sub, client.getClientId(), scopes,
                    refreshTokenValidity(client), accessTokenValue, clientCredentials));
            map.put("refresh_token", refreshTokenValue);
        }

        if (isOpenIDRequest(scopes)) {
            map.put("id_token", tokenGenerator.generateIDTokenForTokenEndpoint(user, client, idTokenClaims));
        }

        addSharedProperties(map, client);
        return map;
    }

    default Map<String, Object> authorizationEndpointResponse(User user, OpenIDClient client, AuthorizationRequest authorizationRequest,
                                                              List<String> scopes, ResponseType responseType) throws JOSEException {
        Map<String, Object> map = new HashMap<>();
        String value = getTokenGenerator().generateAccessTokenWithEmbeddedUserInfo(user, client, scopes);
        if (AccessTokenHash.isRequiredInIDTokenClaims(responseType) || !isOpenIDRequest(authorizationRequest)) {
            getAccessTokenRepository().insert(new AccessToken(value, user.getSub(), client.getClientId(), scopes,
                    accessTokenValidity(client), false));
            map.put("access_token", value);
        }
        if (isOpenIDRequest(authorizationRequest)) {
            AuthenticationRequest authenticationRequest = (AuthenticationRequest) authorizationRequest;
            List<String> claims = getClaims(authorizationRequest);
            String idToken = getTokenGenerator().generateIDTokenForAuthorizationEndpoint(
                    user, client, authenticationRequest.getNonce(), responseType, value, claims);
            map.put("id_token", idToken);
        }
        addSharedProperties(map, client);
        return map;
    }

    default boolean isOpenIDRequest(AuthorizationRequest authorizationRequest) {
        return authorizationRequest instanceof AuthenticationRequest;
    }

    default boolean isOpenIDRequest(List<String> scopes) {
        return scopes.contains("openid");
    }

    default List<String> getClaims(AuthorizationRequest authorizationRequest) {
        List<String> idTokenClaims = new ArrayList<>();
        if (isOpenIDRequest(authorizationRequest)) {
            AuthenticationRequest authenticationRequest = (AuthenticationRequest) authorizationRequest;
            ClaimsRequest claimsRequest = authenticationRequest.getClaims();
            if (claimsRequest != null) {
                idTokenClaims.addAll(
                        claimsRequest.getIDTokenClaims().stream()
                                .map(entry -> entry.getClaimName())
                                .collect(Collectors.toList()));
            }
        }
        return idTokenClaims;
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
