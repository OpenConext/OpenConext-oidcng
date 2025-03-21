package oidc.endpoints;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import oidc.model.OpenIDClient;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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
                                .map(ClaimsRequest.Entry::getClaimName)
                                .toList());
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

    default void logout(HttpServletRequest request) {
        SecurityContextHolder.getContext().setAuthentication(null);
        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }


}
