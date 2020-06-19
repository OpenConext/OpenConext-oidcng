package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import oidc.crypto.KeyGenerator;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.EncryptedTokenValue;
import oidc.model.OpenIDClient;
import oidc.model.RefreshToken;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.repository.RefreshTokenRepository;
import oidc.secure.TokenGenerator;
import org.springframework.security.core.context.SecurityContextHolder;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public interface OidcEndpoint {

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
