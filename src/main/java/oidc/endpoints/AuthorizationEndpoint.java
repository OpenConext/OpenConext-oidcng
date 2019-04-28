package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
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
import oidc.repository.UserRepository;
import oidc.secure.TokenGenerator;
import oidc.user.OidcSamlAuthentication;
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
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class AuthorizationEndpoint implements OidcEndpoint {

    private TokenGenerator tokenGenerator;
    private AuthorizationCodeRepository authorizationCodeRepository;
    private UserRepository userRepository;
    private AccessTokenRepository accessTokenRepository;
    private OpenIDClientRepository openIDClientRepository;
    private List<String> forFreeOpenIDScopes = Arrays.asList("profile", "email", "address", "phone");

    @Autowired
    public AuthorizationEndpoint(AuthorizationCodeRepository authorizationCodeRepository,
                                 AccessTokenRepository accessTokenRepository,
                                 UserRepository userRepository,
                                 OpenIDClientRepository openIDClientRepository,
                                 TokenGenerator tokenGenerator) {
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.accessTokenRepository = accessTokenRepository;
        this.userRepository = userRepository;
        this.openIDClientRepository = openIDClientRepository;
        this.tokenGenerator = tokenGenerator;
    }

    @GetMapping("/oidc/authorize")
    public ModelAndView authorize(@RequestParam MultiValueMap<String, String> parameters,
                                  Authentication authentication) throws ParseException, JOSEException, UnsupportedEncodingException {
        return doAuthorize(parameters, authentication);
    }

    private ModelAndView doAuthorize(@RequestParam MultiValueMap<String, String> parameters, Authentication authentication) throws ParseException, JOSEException, UnsupportedEncodingException {
        OidcSamlAuthentication samlAuthentication = (OidcSamlAuthentication) authentication;
        AuthenticationRequest authenticationRequest = AuthenticationRequest.parse(parameters);
        Scope scope = authenticationRequest.getScope();
        State state = authenticationRequest.getState();

        OpenIDClient client = openIDClientRepository.findByClientId(authenticationRequest.getClientID().getValue());
        String redirectionURI = authenticationRequest.getRedirectionURI().toString();
        redirectionURI = URLDecoder.decode(redirectionURI, Charset.defaultCharset().toString());
        validateRedirectionURI(redirectionURI, client);

        List<String> scopes = scope.toStringList();
        validateScopes(scopes, client);

        User user = samlAuthentication.getUser();

        ResponseType responseType = authenticationRequest.getResponseType();
        if (responseType.impliesCodeFlow()) {
            String code = tokenGenerator.generateAuthorizationCode();
            AuthorizationCode authorizationCode = constructAuthorizationCode(authenticationRequest, client, user, code);
            authorizationCodeRepository.insert(authorizationCode);
            return new ModelAndView(new RedirectView(authorizationRedirect(redirectionURI, state, code)));
        } else if (responseType.impliesImplicitFlow()) {
            Map<String, Object> body = authorizationEndpointResponse(user, client, authenticationRequest.getNonce(), scopes, responseType);
            if (state != null) {
                body.put("state", state);
            }
            ResponseMode responseMode = authenticationRequest.impliedResponseMode();
            if (responseMode.equals(ResponseMode.FORM_POST)) {
                return new ModelAndView("form_post", body);
            }
            if (responseMode.equals(ResponseMode.QUERY)) {
                UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectionURI);
                body.forEach((key, value) -> builder.queryParam(key, value));
                return new ModelAndView(new RedirectView(builder.toUriString()));
            } else {
                UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectionURI);
                //builder.fragment()TODO
                body.forEach((key, value) -> builder.queryParam(key, value));
                return new ModelAndView(new RedirectView(builder.toUriString()));
            }
        } else if (responseType.impliesHybridFlow()) {
            //TODO
        }
        throw new IllegalArgumentException("Not yet implemented response_type: " + responseType.toString());
    }

    private AuthorizationCode constructAuthorizationCode(AuthenticationRequest authenticationRequest, OpenIDClient client, User user, String code) {
        String redirectionURI = authenticationRequest.getRedirectionURI().toString();
        List<String> scopes = authenticationRequest.getScope().toStringList();
        //Optional code challenges for PKCE
        CodeChallenge codeChallenge = authenticationRequest.getCodeChallenge();
        String codeChallengeValue = codeChallenge != null ? codeChallenge.getValue() : null;
        CodeChallengeMethod codeChallengeMethod = authenticationRequest.getCodeChallengeMethod();
        String codeChallengeMethodValue = codeChallengeMethod != null ? codeChallengeMethod.getValue() :
                (codeChallengeValue != null ? CodeChallengeMethod.getDefault().getValue() : null);

        return new AuthorizationCode(
                code, user.getSub(), client.getClientId(), scopes, redirectionURI,
                codeChallengeValue,
                codeChallengeMethodValue);
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
        return builder.toUriString();
    }


    private void validateScopes(List<String> requestedScopes, OpenIDClient client) {
        List<String> scopes = client.getScopes();
        scopes.addAll(forFreeOpenIDScopes);
        if (!scopes.containsAll(requestedScopes)) {
            List<String> missingScopes = requestedScopes.stream().filter(s -> !scopes.contains(s)).collect(Collectors.toList());
            throw new InvalidScopeException(
                    String.format("Scope(s) %s are not allowed for findByClientId %s", missingScopes, client.getClientId()));
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
}
