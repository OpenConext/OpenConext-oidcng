package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.Prompt;
import oidc.crypto.KeyGenerator;
import oidc.exceptions.InvalidGrantException;
import oidc.exceptions.InvalidScopeException;
import oidc.exceptions.RedirectMismatchException;
import oidc.exceptions.UnknownClientException;
import oidc.exceptions.UnsupportedPromptValueException;
import oidc.log.MDCContext;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.EncryptedTokenValue;
import oidc.model.OpenIDClient;
import oidc.model.ProvidedRedirectURI;
import oidc.model.TokenValue;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.repository.AuthorizationCodeRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.repository.UserRepository;
import oidc.secure.JWTRequest;
import oidc.secure.TokenGenerator;
import oidc.user.OidcSamlAuthentication;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

@Controller
public class AuthorizationEndpoint implements OidcEndpoint {

    private static final Log LOG = LogFactory.getLog(AuthorizationEndpoint.class);
    private static final List<String> forFreeOpenIDScopes = Arrays.asList("openid", "profile", "email", "address", "phone");

    private final TokenGenerator tokenGenerator;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final AccessTokenRepository accessTokenRepository;
    private final UserRepository userRepository;
    private final OpenIDClientRepository openIDClientRepository;
    private final String salt;
    private final String environment;
    private final boolean consentEnabled;

    @Autowired
    public AuthorizationEndpoint(AuthorizationCodeRepository authorizationCodeRepository,
                                 AccessTokenRepository accessTokenRepository,
                                 UserRepository userRepository,
                                 OpenIDClientRepository openIDClientRepository,
                                 TokenGenerator tokenGenerator,
                                 @Value("${access_token_one_way_hash_salt}") String salt,
                                 @Value("${environment}") String environment,
                                 @Value("${features.consent-enabled}") boolean consentEnabled) {
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.accessTokenRepository = accessTokenRepository;
        this.userRepository = userRepository;
        this.openIDClientRepository = openIDClientRepository;
        this.tokenGenerator = tokenGenerator;
        this.salt = salt;
        this.environment = environment;
        this.consentEnabled = consentEnabled;
    }

    @GetMapping("/oidc/authorize")
    public ModelAndView authorize(@RequestParam MultiValueMap<String, String> parameters,
                                  Authentication authentication,
                                  HttpServletRequest request) throws ParseException, JOSEException, IOException, CertificateException, BadJOSEException, java.text.ParseException, URISyntaxException {
        LOG.debug(String.format("/oidc/authorize %s %s", authentication.getDetails(), parameters));

        //to enable consent, set consentRequired to true
        return doAuthorization(parameters, (OidcSamlAuthentication) authentication, request, consentEnabled);
    }

    @PostMapping(value = "/oidc/consent", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ModelAndView consent(@RequestParam Map<String, String> body,
                                Authentication authentication,
                                HttpServletRequest request) throws ParseException, JOSEException, IOException, CertificateException, BadJOSEException, java.text.ParseException, URISyntaxException {
        LOG.debug(String.format("/oidc/consent %s %s", authentication.getDetails(), body));

        LinkedMultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.setAll(body);
        return this.doAuthorization(parameters, (OidcSamlAuthentication) authentication, request, false);
    }

    private ModelAndView doAuthorization(MultiValueMap<String, String> parameters,
                                         OidcSamlAuthentication samlAuthentication,
                                         HttpServletRequest request,
                                         boolean consentRequired) throws ParseException, CertificateException, JOSEException, IOException, BadJOSEException, java.text.ParseException, URISyntaxException {
        AuthorizationRequest authenticationRequest = AuthorizationRequest.parse(parameters);

        Scope scope = authenticationRequest.getScope();
        boolean isOpenIdClient = scope != null && isOpenIDRequest(scope.toStringList());

        String clientId = authenticationRequest.getClientID().getValue();
        OpenIDClient client = openIDClientRepository
                .findOptionalByClientId(clientId)
                .orElseThrow(() -> new UnknownClientException(clientId));
        MDCContext.mdcContext("action", "Authorize", "rp", client.getClientId());
        if (isOpenIdClient) {
            AuthenticationRequest oidcAuthenticationRequest = AuthenticationRequest.parse(parameters);
            if (oidcAuthenticationRequest.specifiesRequestObject()) {
                oidcAuthenticationRequest = JWTRequest.parse(oidcAuthenticationRequest, client);
                LOG.debug("/oidc/authorize with JWT 'request'");
            }
            //swap reference
            authenticationRequest = oidcAuthenticationRequest;
        }
        State state = authenticationRequest.getState();
        String redirectURI = validateRedirectionURI(authenticationRequest.getRedirectionURI(), client).getRedirectURI();

        List<String> scopes = validateScopes(openIDClientRepository, authenticationRequest.getScope(), client);
        ResponseType responseType = validateGrantType(authenticationRequest, client);

        User user = samlAuthentication.getUser();
        MDCContext.mdcContext(user);

        if (scope != null) {
            List<String> scopeList = scope.toStringList();
            boolean apiScopeRequested = !(scopeList.size() == 0 || (scopeList.size() == 1 && scopeList.contains("openid")));
            Set<String> filteredScopes = scopeList.stream()
                    .filter(s -> !s.equalsIgnoreCase("openid"))
                    .map(String::toLowerCase)
                    .collect(toSet());
            List<OpenIDClient> resourceServers = openIDClientRepository.findByScopes_NameIn(filteredScopes);
            Prompt prompt = authenticationRequest.getPrompt();
            boolean consentFromPrompt = prompt != null && prompt.toStringList().contains("consent");
            /*
             * We prompt for consent when the following conditions are met:
             *   Consent feature toggle is on
             *   The RP has requested scope(s) other then openid
             *   Manage attribute "oidc:consentRequired" is true for the RP or the RP has explicitly asked for consent
             *   There is at least one ResourceServer that has the requested scope(s) configured in manage
             */
            if (consentRequired && apiScopeRequested && (consentFromPrompt || client.isConsentRequired()) && resourceServers.size() > 0) {
                LOG.info("Asking for consent for User " + user + " and scopes " + scopes);
                return doConsent(parameters, client, filteredScopes, resourceServers);
            }
        }
        //We do not provide SSO as does EB not - up to the identity provider
        logout(request);

        ResponseMode responseMode = authenticationRequest.impliedResponseMode();

        if (responseType.impliesCodeFlow()) {
            AuthorizationCode authorizationCode = createAndSaveAuthorizationCode(authenticationRequest, client, user);
            LOG.debug(String.format("Returning authorizationCode flow %s %s", ResponseMode.FORM_POST, redirectURI));
            if (responseMode.equals(ResponseMode.FORM_POST)) {
                Map<String, String> body = new HashMap<>();
                body.put("redirect_uri", redirectURI);
                body.put("code", authorizationCode.getCode());
                if (state != null && StringUtils.hasText(state.getValue())) {
                    body.put("state", state.getValue());
                }
                return new ModelAndView("form_post", body);
            }
            return new ModelAndView(new RedirectView(authorizationRedirect(redirectURI, state,
                    authorizationCode.getCode(), responseMode.equals(ResponseMode.FRAGMENT))));
        } else if (responseType.impliesImplicitFlow() || responseType.impliesHybridFlow()) {
            if (responseType.impliesImplicitFlow()) {
                //User information is encrypted in access token
                LOG.debug("Deleting user " + user.getSub());
                userRepository.delete(user);
            }
            Map<String, Object> body = authorizationEndpointResponse(user, client, authenticationRequest, scopes, responseType, state);

            LOG.debug(String.format("Returning implicit flow %s %s", ResponseMode.FORM_POST, redirectURI));
            if (responseMode.equals(ResponseMode.FORM_POST)) {
                body.put("redirect_uri", redirectURI);
                return new ModelAndView("form_post", body);
            }
            if (responseMode.equals(ResponseMode.QUERY)) {
                UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectURI);
                body.forEach(builder::queryParam);
                return new ModelAndView(new RedirectView(builder.toUriString()));
            }
            if (responseMode.equals(ResponseMode.FRAGMENT)) {
                UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectURI);
                String fragment = body.entrySet().stream().map(entry -> String.format("%s=%s", entry.getKey(), entry.getValue())).collect(Collectors.joining("&"));
                builder.fragment(fragment);
                return new ModelAndView(new RedirectView(builder.toUriString()));
            }
            throw new IllegalArgumentException("Response mode " + responseMode + " not supported");
        }
        throw new IllegalArgumentException("Not yet implemented response_type: " + responseType.toString());
    }

    private void logout(HttpServletRequest request) {
        SecurityContextHolder.getContext().setAuthentication(null);
        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }

    private ModelAndView doConsent(MultiValueMap<String, String> parameters, OpenIDClient client, Set<String> scopes, List<OpenIDClient> resourceServers) {
        Map<String, Object> body = new HashMap<>();
        body.put("parameters", parameters.entrySet().stream().collect(Collectors.toMap(
                Map.Entry::getKey,
                entry -> entry.getValue().get(0)
        )));
        body.put("client", client);
        body.put("resourceServers", resourceServers.stream().filter(rs -> StringUtils.hasText(rs.getLogoUrl())).collect(toList()));
        body.put("scopes", resourceServers.stream()
                .map(OpenIDClient::getScopes)
                .flatMap(List::stream)
                .filter(scope -> scopes.contains(scope.getName().toLowerCase()))
                .collect(Collectors.toSet()));
        Locale locale = LocaleContextHolder.getLocale();
        body.put("lang", locale.getLanguage());
        body.put("environment", environment);
        return new ModelAndView("consent", body);
    }

    public static ResponseType validateGrantType(AuthorizationRequest authorizationRequest, OpenIDClient client) {
        ResponseType responseType = authorizationRequest.getResponseType();
        List<String> grants = client.getGrants();
        if ((responseType.impliesImplicitFlow() || responseType.impliesHybridFlow()) && !grants.contains(GrantType.IMPLICIT.getValue())) {
            throw new InvalidGrantException(String.format("Grant types %s does not allow for implicit / hybrid flow", grants));
        }
        if (responseType.impliesCodeFlow() && !grants.contains(GrantType.AUTHORIZATION_CODE.getValue())) {
            throw new InvalidGrantException(String.format("Grant types %s does not allow for authorization code flow", grants));
        }
        return responseType;
    }

    private Map<String, Object> authorizationEndpointResponse(User user, OpenIDClient client, AuthorizationRequest authorizationRequest,
                                                              List<String> scopes, ResponseType responseType, State state) {
        Map<String, Object> result = new LinkedHashMap<>();
        EncryptedTokenValue encryptedAccessToken = tokenGenerator.generateAccessTokenWithEmbeddedUserInfo(user, client, scopes);
        if (responseType.contains(ResponseType.Value.TOKEN.getValue()) || !isOpenIDRequest(authorizationRequest)) {
            String unspecifiedUrnHash = KeyGenerator.oneWayHash(user.getUnspecifiedNameId(), this.salt);
            AccessToken accessToken = new AccessToken(encryptedAccessToken.getJwtId(), user.getSub(), client.getClientId(), scopes,
                    encryptedAccessToken.getKeyId(), accessTokenValidity(client), false, null, unspecifiedUrnHash);
            accessTokenRepository.insert(accessToken);
            result.put("access_token", encryptedAccessToken.getValue());
            result.put("token_type", "Bearer");
        }
        if (responseType.contains(ResponseType.Value.CODE.getValue())) {
            AuthorizationCode authorizationCode = createAndSaveAuthorizationCode(authorizationRequest, client, user);
            result.put("code", authorizationCode.getCode());
        }
        if (responseType.contains(OIDCResponseTypeValue.ID_TOKEN.getValue()) && isOpenIDRequest(scopes) && isOpenIDRequest(authorizationRequest)) {
            AuthenticationRequest authenticationRequest = (AuthenticationRequest) authorizationRequest;
            List<String> claims = getClaims(authorizationRequest);
            TokenValue tokenValue = tokenGenerator.generateIDTokenForAuthorizationEndpoint(
                    user, client, authenticationRequest.getNonce(), responseType, encryptedAccessToken.getValue(), claims,
                    Optional.ofNullable((String) result.get("code")), state);
            result.put("id_token", tokenValue.getValue());
        }
        result.put("expires_in", client.getAccessTokenValidity());
        if (state != null) {
            result.put("state", state.getValue());
        }
        return result;
    }

    private AuthorizationCode createAndSaveAuthorizationCode(AuthorizationRequest authorizationRequest, OpenIDClient client, User user) {
        URI redirectionURI = authorizationRequest.getRedirectionURI();
        Scope scope = authorizationRequest.getScope();
        List<String> scopes = scope != null ? scope.toStringList() : Collections.emptyList();
        //Optional code challenges for PKCE
        CodeChallenge codeChallenge = authorizationRequest.getCodeChallenge();
        String codeChallengeValue = codeChallenge != null ? codeChallenge.getValue() : null;
        CodeChallengeMethod codeChallengeMethod = authorizationRequest.getCodeChallengeMethod();
        String codeChallengeMethodValue = codeChallengeMethod != null ? codeChallengeMethod.getValue() :
                (codeChallengeValue != null ? CodeChallengeMethod.getDefault().getValue() : null);
        List<String> idTokenClaims = getClaims(authorizationRequest);
        String code = tokenGenerator.generateAuthorizationCode();
        Nonce nonce = authorizationRequest instanceof AuthenticationRequest ? AuthenticationRequest.class.cast(authorizationRequest).getNonce() : null;
        AuthorizationCode authorizationCode = new AuthorizationCode(
                code,
                user.getSub(),
                client.getClientId(),
                scopes,
                redirectionURI,
                codeChallengeValue,
                codeChallengeMethodValue,
                nonce != null ? nonce.getValue() : null,
                idTokenClaims,
                redirectionURI != null,
                tokenValidity(10 * 60));

        authorizationCodeRepository.insert(authorizationCode);
        return authorizationCode;
    }

    public static ProvidedRedirectURI validateRedirectionURI(URI redirectionURI, OpenIDClient client) throws UnsupportedEncodingException {
        List<String> registeredRedirectUrls = client.getRedirectUrls();
        if (CollectionUtils.isEmpty(registeredRedirectUrls)) {
            throw new IllegalArgumentException(String.format("Client %s must have at least one redirectURI configured to use the Authorization flow",
                    client.getClientId()));
        }
        if (redirectionURI == null) {
            return new ProvidedRedirectURI(registeredRedirectUrls.get(0));
        }

        String redirectURI = URLDecoder.decode(redirectionURI.toString(), StandardCharsets.UTF_8);
        Optional<ProvidedRedirectURI> optionalProvidedRedirectURI = registeredRedirectUrls.stream()
                .map(ProvidedRedirectURI::new)
                .filter(providedRedirectURI -> providedRedirectURI.equalsIgnorePort(redirectURI))
                .findFirst();
        if (optionalProvidedRedirectURI.isEmpty()) {
            throw new RedirectMismatchException(
                    String.format("Client %s with registered redirect URI's %s requested authorization with redirectURI %s",
                            client.getClientId(), registeredRedirectUrls, redirectURI));
        }
        ProvidedRedirectURI providedRedirectURI = optionalProvidedRedirectURI.get();
        //We return the redirectURI provided by the RP as the port may differ, but only for localhost
        return providedRedirectURI.literalCheckRequired() ? providedRedirectURI : new ProvidedRedirectURI(redirectURI);
    }

    private String authorizationRedirect(String redirectionURI, State state, String code, boolean isFragment) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectionURI);
        boolean hasState = state != null && StringUtils.hasText(state.getValue());
        if (isFragment) {
            String fragment = "code=" + code;
            if (hasState) {
                fragment = fragment.concat("&state=" + state.getValue());
            }
            builder.fragment(fragment);
        } else {
            builder.queryParam("code", code);
            if (hasState) {
                builder.queryParam("state", state.getValue());
            }
        }
        return builder.toUriString();
    }

    private static final String unsupportedPromptMessage = "Unsupported Prompt value";

    public static String validatePrompt(Map<String, List<String>> request) throws ParseException {
        List<String> promptValues = request.get("prompt");
        String promptValue = CollectionUtils.isEmpty(promptValues) ? null : promptValues.get(0);
        Prompt prompt = Prompt.parse(promptValue);
        return validatePrompt(prompt);
    }

    public static String validatePrompt(Prompt prompt) {
        //We trigger an error is prompt is present and not equals 'login' or 'consent'
        if (prompt != null) {
            List<String> allowedValues = Arrays.asList("consent", "login");
            prompt.toStringList().forEach(val -> {
                if (!allowedValues.contains(val)) {
                    throw new UnsupportedPromptValueException(unsupportedPromptValue(val), unsupportedPromptMessage);
                }
            });
        }
        return prompt != null ? prompt.toString() : null;
    }

    private static String unsupportedPromptValue(String prompt) {
        switch (prompt) {
            case "none":
                return "interaction_required";
            case "select_account":
                return "account_selection_required";
            default:
                return "invalid_request";
        }
    }

    public static List<String> validateScopes(OpenIDClientRepository openIDClientRepository, Scope scope, OpenIDClient client) {
        List<String> requestedScopes = scope != null ? scope.toStringList() : Collections.emptyList();

        List<String> allowedResourceServers = client.getAllowedResourceServers();
        List<String> grantedScopes = new ArrayList<>();
        if (!CollectionUtils.isEmpty(allowedResourceServers)) {
            List<OpenIDClient> resourceServers = openIDClientRepository.findByClientIdIn(allowedResourceServers);
            grantedScopes.addAll(resourceServers.stream()
                    .flatMap(rs -> rs.getScopes().stream().map(oidc.model.Scope::getName))
                    .collect(toList()));
        }
        grantedScopes.addAll(forFreeOpenIDScopes);
        //backward compatibility
        grantedScopes.addAll(client.getScopes().stream().map(oidc.model.Scope::getName).collect(toList()));

        if (!grantedScopes.containsAll(requestedScopes)) {
            List<String> missingScopes = requestedScopes.stream().filter(s -> !grantedScopes.contains(s)).collect(toList());
            throw new InvalidScopeException(
                    String.format("Scope(s) %s are not allowed for %s. Allowed scopes: %s",
                            missingScopes, client.getClientId(), client.getScopes()));
        }
        return requestedScopes;
    }
}
