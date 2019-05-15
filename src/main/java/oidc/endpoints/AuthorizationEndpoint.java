package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import oidc.exceptions.InvalidScopeException;
import oidc.exceptions.RedirectMismatchException;
import oidc.model.AuthorizationCode;
import oidc.model.OpenIDClient;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.repository.AuthorizationCodeRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.repository.RefreshTokenRepository;
import oidc.secure.TokenGenerator;
import oidc.user.OidcSamlAuthentication;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class AuthorizationEndpoint implements OidcEndpoint {

    private static final Log LOG = LogFactory.getLog(AuthorizationEndpoint.class);

    private TokenGenerator tokenGenerator;
    private AuthorizationCodeRepository authorizationCodeRepository;
    private AccessTokenRepository accessTokenRepository;
    private RefreshTokenRepository refreshTokenRepository;
    private OpenIDClientRepository openIDClientRepository;
    private List<String> forFreeOpenIDScopes = Arrays.asList("profile", "email", "address", "phone");

    @Autowired
    public AuthorizationEndpoint(AuthorizationCodeRepository authorizationCodeRepository,
                                 AccessTokenRepository accessTokenRepository,
                                 RefreshTokenRepository refreshTokenRepository,
                                 OpenIDClientRepository openIDClientRepository,
                                 TokenGenerator tokenGenerator) {
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.openIDClientRepository = openIDClientRepository;
        this.tokenGenerator = tokenGenerator;
    }

    @GetMapping("/oidc/authorize")
    public ModelAndView authorize(@RequestParam MultiValueMap<String, String> parameters,
                                  Authentication authentication) throws ParseException, JOSEException, UnsupportedEncodingException {
        LOG.info(String.format("doAuthorize %s %s", authentication.getDetails(), parameters));

        OidcSamlAuthentication samlAuthentication = (OidcSamlAuthentication) authentication;
        AuthorizationRequest authenticationRequest = AuthorizationRequest.parse(parameters);

        Scope scope = authenticationRequest.getScope();
        boolean isOpenIdClient = scope != null && isOpenIDRequest(scope.toStringList());
        if (isOpenIdClient) {
            authenticationRequest = AuthenticationRequest.parse(parameters);
        }
        State state = authenticationRequest.getState();

        OpenIDClient client = openIDClientRepository.findByClientId(authenticationRequest.getClientID().getValue());
        String redirectionURI = authenticationRequest.getRedirectionURI().toString();
        redirectionURI = URLDecoder.decode(redirectionURI, Charset.defaultCharset().toString());
        validateRedirectionURI(redirectionURI, client);

        List<String> scopes = scope != null ? scope.toStringList() : Collections.emptyList();
        validateScopes(scopes, client);

        User user = samlAuthentication.getUser();

        ResponseType responseType = authenticationRequest.getResponseType();
        if (responseType.impliesCodeFlow()) {
            String code = tokenGenerator.generateAuthorizationCode();
            AuthorizationCode authorizationCode = constructAuthorizationCode(authenticationRequest, client, user, code);
            authorizationCodeRepository.insert(authorizationCode);
            return new ModelAndView(new RedirectView(authorizationRedirect(redirectionURI, state, code)));
        } else if (responseType.impliesImplicitFlow()) {
            Map<String, Object> body = authorizationEndpointResponse(user, client, authenticationRequest, scopes, responseType);
            if (state != null) {
                body.put("state", state);
            }
            ResponseMode responseMode = authenticationRequest.impliedResponseMode();
            if (responseMode.equals(ResponseMode.FORM_POST)) {
                body.put("redirect_uri", redirectionURI);
                LOG.info(String.format("Returning implicit flow %s %s", ResponseMode.FORM_POST, redirectionURI));
                return new ModelAndView("form_post", body);
            }
            if (responseMode.equals(ResponseMode.QUERY)) {
                UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectionURI);
                body.forEach(builder::queryParam);
                LOG.info(String.format("Returning implicit flow %s %s", ResponseMode.QUERY, redirectionURI));
                return new ModelAndView(new RedirectView(builder.toUriString()));
            }
            if (responseMode.equals(ResponseMode.FRAGMENT)) {
                UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectionURI);
                String fragment = body.entrySet().stream().map(entry -> String.format("%s=%s", entry.getKey(), entry.getValue())).collect(Collectors.joining("&"));
                builder.fragment(fragment);
                LOG.info(String.format("Returning implicit flow %s %s", ResponseMode.FRAGMENT, redirectionURI));
                return new ModelAndView(new RedirectView(builder.toUriString()));
            }
            throw new IllegalArgumentException("Response mode " + responseMode + " not supported");
        } else if (responseType.impliesHybridFlow()) {
            //TODO
        }
        throw new IllegalArgumentException("Not yet implemented response_type: " + responseType.toString());
    }

    private AuthorizationCode constructAuthorizationCode(AuthorizationRequest authorizationRequest, OpenIDClient client, User user, String code) {
        String redirectionURI = authorizationRequest.getRedirectionURI().toString();
        List<String> scopes = authorizationRequest.getScope().toStringList();
        //Optional code challenges for PKCE
        CodeChallenge codeChallenge = authorizationRequest.getCodeChallenge();
        String codeChallengeValue = codeChallenge != null ? codeChallenge.getValue() : null;
        CodeChallengeMethod codeChallengeMethod = authorizationRequest.getCodeChallengeMethod();
        String codeChallengeMethodValue = codeChallengeMethod != null ? codeChallengeMethod.getValue() :
                (codeChallengeValue != null ? CodeChallengeMethod.getDefault().getValue() : null);
        List<String> idTokenClaims = getClaims(authorizationRequest);
        return new AuthorizationCode(
                code, user.getSub(), client.getClientId(), scopes, redirectionURI,
                codeChallengeValue,
                codeChallengeMethodValue,
                idTokenClaims,
                tokenValidity(5 * 60));
    }

    private void validateRedirectionURI(String redirectionURI, OpenIDClient client) {
        if (!client.getRedirectUrls().contains(redirectionURI)) {
            throw new RedirectMismatchException(
                    String.format("Client %s with registered redirect URI's %s requested authorization with redirectURI %s",
                            client.getClientId(), client.getRedirectUrls(), redirectionURI));
        }
    }

    private String authorizationRedirect(String redirectionURI, State state, String code) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectionURI).queryParam("code", code);
        if (state != null && StringUtils.hasText(state.getValue())) {
            builder.queryParam("state", state.getValue());
        }
        String result = builder.toUriString();
        LOG.info("Returning authorizationRedirect: " + result);
        return result;
    }


    private void validateScopes(List<String> requestedScopes, OpenIDClient client) {
        List<String> scopes = client.getScopes();
        scopes.addAll(forFreeOpenIDScopes);
        if (!scopes.containsAll(requestedScopes)) {
            List<String> missingScopes = requestedScopes.stream().filter(s -> !scopes.contains(s)).collect(Collectors.toList());
            throw new InvalidScopeException(
                    String.format("Scope(s) %s are not allowed for %s. Allowed scopes: %s",
                            missingScopes, client.getClientId(), client.getScopes()));
        }

    }

    @Override
    public TokenGenerator getTokenGenerator() {
        return tokenGenerator;
    }

    @Override
    public AccessTokenRepository getAccessTokenRepository() {
        return accessTokenRepository;
    }

    @Override
    public RefreshTokenRepository getRefreshTokenRepository() {
        return refreshTokenRepository;
    }
}
