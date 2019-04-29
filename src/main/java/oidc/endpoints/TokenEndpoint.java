package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import oidc.exceptions.ClientAuthenticationNotSupported;
import oidc.exceptions.CodeVerifierMissingException;
import oidc.exceptions.InvalidGrantException;
import oidc.exceptions.RedirectMismatchException;
import oidc.model.AuthorizationCode;
import oidc.model.OpenIDClient;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.repository.AuthorizationCodeRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.repository.UserRepository;
import oidc.secure.TokenGenerator;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;

import static org.apache.http.entity.ContentType.APPLICATION_JSON;

@RestController
public class TokenEndpoint implements OidcEndpoint{

    private AuthorizationCodeRepository authorizationCodeRepository;
    private AccessTokenRepository accessTokenRepository;
    private UserRepository userRepository;
    private OpenIDClientRepository openIDClientRepository;
    private TokenGenerator tokenGenerator;
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public TokenEndpoint(OpenIDClientRepository openIDClientRepository,
                         AuthorizationCodeRepository authorizationCodeRepository,
                         AccessTokenRepository accessTokenRepository,
                         UserRepository userRepository,
                         TokenGenerator tokenGenerator) {
        this.openIDClientRepository = openIDClientRepository;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.accessTokenRepository = accessTokenRepository;
        this.userRepository = userRepository;
        this.tokenGenerator = tokenGenerator;
    }

    @PostMapping(value = "oidc/token", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ResponseEntity token(HttpServletRequest request) throws IOException, ParseException, JOSEException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
        TokenRequest tokenRequest = TokenRequest.parse(httpRequest);

        ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();
        if (clientAuthentication != null &&
                !(clientAuthentication instanceof PlainClientSecret)) {
            throw new ClientAuthenticationNotSupported(
                    String.format("Unsupported '%s' findByClientId authentication in token endpoint", clientAuthentication.getClass()));
        }
        AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();
        if (clientAuthentication == null && authorizationGrant instanceof AuthorizationCodeGrant
                && ((AuthorizationCodeGrant) authorizationGrant).getCodeVerifier() == null) {
            throw new CodeVerifierMissingException("code_verifier required without findByClientId authentication");
        }

        OpenIDClient client = openIDClientRepository.findByClientId(clientAuthentication.getClientID().getValue());

        if (clientAuthentication != null &&
                !secretsMatch(PlainClientSecret.class.cast(clientAuthentication), client)) {
            throw new BadCredentialsException("Invalid user / secret");
        }
        if (!client.getGrants().contains(authorizationGrant.getType().getValue())) {
            throw new InvalidGrantException("Invalid grant");
        }

        if (authorizationGrant instanceof AuthorizationCodeGrant) {
            return handleAuthorizationCodeGrant((AuthorizationCodeGrant) authorizationGrant, client);
        } else if (authorizationGrant instanceof ClientCredentialsGrant) {
            return handleClientCredentialsGrant(client);
        }
        throw new IllegalArgumentException("Not supported - yet - authorizationGrant " + authorizationGrant);

    }

    @Override
    public TokenGenerator getTokenGenerator() {
        return tokenGenerator;
    }

    @Override
    public AccessTokenRepository getAccessTokenRepository() {
        return accessTokenRepository;
    }

    //See https://www.pivotaltracker.com/story/show/165565558
    private boolean secretsMatch(PlainClientSecret clientSecret, OpenIDClient openIDClient) {
        return passwordEncoder.matches(clientSecret.getClientSecret().getValue(), openIDClient.getSecret());
    }

    private ResponseEntity handleAuthorizationCodeGrant(AuthorizationCodeGrant authorizationCodeGrant, OpenIDClient client) throws JOSEException {
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
        CodeVerifier codeVerifier = authorizationCodeGrant.getCodeVerifier();
        if (codeVerifier != null)  {
            if (authorizationCode.getCodeChallenge() == null) {
                throw new CodeVerifierMissingException("code_verifier present but not in the authorization_code");
            }
            CodeChallenge computed = CodeChallenge.compute(CodeChallengeMethod.parse(authorizationCode.getCodeChallengeMethod()), codeVerifier);

            if (!codeVerifier.getValue().equals(computed.getValue())) {
                throw new CodeVerifierMissingException("code_verifier does not match code_challenge");
            }
        }
        authorizationCodeRepository.delete(authorizationCode);
        User user = userRepository.findUserBySub(authorizationCode.getSub());
        Map<String, Object> body = tokenEndpointResponse(Optional.of(user), client, authorizationCode.getScopes());
        return new ResponseEntity<>(body, getResponseHeaders(), HttpStatus.OK);
    }

    private ResponseEntity handleClientCredentialsGrant(OpenIDClient client) throws JOSEException {
        Map<String, Object> body = tokenEndpointResponse(Optional.empty(), client, client.getScopes());
        return new ResponseEntity<>(body, getResponseHeaders(), HttpStatus.OK);
    }

    private HttpHeaders getResponseHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.CACHE_CONTROL, "no-store");
        headers.set(HttpHeaders.CONTENT_TYPE, APPLICATION_JSON.getMimeType());
        headers.set(HttpHeaders.PRAGMA, "no-cache");
        return headers;
    }

}
