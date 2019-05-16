package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.OpenIDClient;
import oidc.model.RefreshToken;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.repository.RefreshTokenRepository;
import oidc.repository.UserRepository;
import oidc.secure.TokenGenerator;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public interface OidcEndpoint {

    default Map<String, Object> tokenEndpointResponse(Optional<User> user, OpenIDClient client,
                                                      List<String> scopes, List<String> idTokenClaims,
                                                      boolean clientCredentials) throws JOSEException {
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

    default AuthorizationCode constructAuthorizationCode(AuthorizationRequest authorizationRequest, OpenIDClient client, User user) {
        String redirectionURI = authorizationRequest.getRedirectionURI().toString();
        Scope scope = authorizationRequest.getScope();
        List<String> scopes = scope != null ? scope.toStringList() : Collections.emptyList();
        //Optional code challenges for PKCE
        CodeChallenge codeChallenge = authorizationRequest.getCodeChallenge();
        String codeChallengeValue = codeChallenge != null ? codeChallenge.getValue() : null;
        CodeChallengeMethod codeChallengeMethod = authorizationRequest.getCodeChallengeMethod();
        String codeChallengeMethodValue = codeChallengeMethod != null ? codeChallengeMethod.getValue() :
                (codeChallengeValue != null ? CodeChallengeMethod.getDefault().getValue() : null);
        List<String> idTokenClaims = getClaims(authorizationRequest);
        String code = getTokenGenerator().generateAuthorizationCode();
        return new AuthorizationCode(
                code, user.getSub(), client.getClientId(), scopes, redirectionURI,
                codeChallengeValue,
                codeChallengeMethodValue,
                idTokenClaims,
                tokenValidity(10 * 60));
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

    default void logout(User user) {
        //User information is encrypted in access token
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.getContext().setAuthentication(null);
        SecurityContextHolder.clearContext();
        getUserRepository().delete(user);
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

    UserRepository getUserRepository();

    AccessTokenRepository getAccessTokenRepository();

    RefreshTokenRepository getRefreshTokenRepository();
}
