package oidc.endpoints;

import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import oidc.exceptions.ClientAuthenticationNotSupported;
import oidc.exceptions.RedirectMismatchException;
import oidc.manage.Manage;
import oidc.model.AuthorizationCode;
import oidc.model.OpenIDClient;
import oidc.repository.AuthorizationCodeRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.GrantType.AUTHORIZATION_CODE;

@RestController
public class TokenEndpoint {

    private Manage manage;
    private AuthorizationCodeRepository authorizationCodeRepository;

    public TokenEndpoint(Manage manage, AuthorizationCodeRepository authorizationCodeRepository) {
        this.manage = manage;
        this.authorizationCodeRepository = authorizationCodeRepository;
    }

    @PostMapping(value = "oidc/token", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ResponseEntity token(HttpServletRequest request) throws IOException, ParseException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
        TokenRequest tokenRequest = TokenRequest.parse(httpRequest);

        ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();

        if (!(clientAuthentication instanceof ClientSecretBasic)) {
            throw new ClientAuthenticationNotSupported(
                    String.format("Unsupported client authentication in token  endpoint", clientAuthentication.getClass()));
        }

        OpenIDClient client = manage.client(clientAuthentication.getClientID().getValue());

        //Pending on resolution of https://www.pivotaltracker.com/story/show/165565558
        if (!ClientSecretBasic.class.cast(clientAuthentication).getClientSecret().getValue().equals(client.getSecret())) {
            throw new BadCredentialsException("Secrets do not match");
        }

        AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();
        if (authorizationGrant instanceof AuthorizationCodeGrant) {
            return handleAuthorizationCodeGrant(AuthorizationCodeGrant.class.cast(authorizationGrant),
                    client,tokenRequest.getScope() );
        }
        throw new IllegalArgumentException("Not supported - yet - authorizationGrant "+ authorizationGrant);
        //return a 'OIDCTokens'
    }

    /*
    DefaultOAuth2ProviderTokenService
ConnectTokenEnhancer
DefaultJWTSigningAndValidationService
DefaultOIDCTokenService
OAuth2AccessTokenEntity
TokenEndpoint#195
     */
    private ResponseEntity handleAuthorizationCodeGrant(AuthorizationCodeGrant authorizationCodeGrant, OpenIDClient client, Scope scope) {
        String code = authorizationCodeGrant.getAuthorizationCode().getValue();
        AuthorizationCode authorizationCode = authorizationCodeRepository.findByCode(code);
        if (authorizationCode == null) {
            throw new BadCredentialsException("Authorization code not found");
        }
        if (!authorizationCode.getClientId().equals(client.getClientId())) {
            throw new BadCredentialsException("Client is not authorized for the authorization code");
        }
        if (authorizationCodeGrant.getRedirectionURI() != null &&
                !authorizationCodeGrant.getRedirectionURI().toString().equals(authorizationCode.getRedirectUri())) {
            throw new RedirectMismatchException("Redirects do not match");
        }

        return new ResponseEntity<Map<String, String>>(null, getResponseHeaders(), HttpStatus.OK);

    }

    private HttpHeaders getResponseHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Cache-Control", "no-store");
        headers.set("Pragma", "no-cache");
        return headers;
    }

}
