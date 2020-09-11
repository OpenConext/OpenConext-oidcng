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
import oidc.exceptions.UnauthorizedException;
import oidc.exceptions.UnsupportedPromptValueException;
import oidc.log.MDCContext;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.EncryptedTokenValue;
import oidc.model.OpenIDClient;
import oidc.model.ProvidedRedirectURI;
import oidc.model.User;
import oidc.model.UserConsent;
import oidc.repository.AccessTokenRepository;
import oidc.repository.AuthorizationCodeRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.repository.RefreshTokenRepository;
import oidc.repository.UserConsentRepository;
import oidc.repository.UserRepository;
import oidc.secure.JWTRequest;
import oidc.secure.TokenGenerator;
import oidc.user.OidcSamlAuthentication;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;
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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;
import static oidc.web.ConfigurableSamlAuthenticationRequestFilter.AUTHENTICATION_REQUEST_ID;

@Controller
public class AuthorizationEndpoint implements OidcEndpoint {

    private static final Log LOG = LogFactory.getLog(AuthorizationEndpoint.class);
    private static final List<String> forFreeOpenIDScopes = Arrays.asList("profile", "email", "address", "phone");

    private final TokenGenerator tokenGenerator;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final AccessTokenRepository accessTokenRepository;
    private final UserRepository userRepository;
    private final UserConsentRepository userConsentRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final OpenIDClientRepository openIDClientRepository;
    private final String salt;

    @Autowired
    public AuthorizationEndpoint(AuthorizationCodeRepository authorizationCodeRepository,
                                 AccessTokenRepository accessTokenRepository,
                                 RefreshTokenRepository refreshTokenRepository,
                                 UserRepository userRepository,
                                 UserConsentRepository userConsentRepository,
                                 OpenIDClientRepository openIDClientRepository,
                                 TokenGenerator tokenGenerator,
                                 @Value("${access_token_one_way_hash_salt}") String salt) {
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.userConsentRepository = userConsentRepository;
        this.openIDClientRepository = openIDClientRepository;
        this.tokenGenerator = tokenGenerator;
        this.salt = salt;
    }

    @GetMapping("/oidc/authorize")
    public ModelAndView authorize(@RequestParam MultiValueMap<String, String> parameters,
                                  Authentication authentication,
                                  HttpServletRequest request) throws ParseException, JOSEException, IOException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, BadJOSEException, java.text.ParseException, URISyntaxException {
        if (authentication == null && request.getAttribute(AUTHENTICATION_REQUEST_ID) == null) {
            throw new UnauthorizedException("no_authentication");
        }
        OidcSamlAuthentication oidcSamlAuthentication = authentication instanceof OidcSamlAuthentication ? (OidcSamlAuthentication) authentication : (OidcSamlAuthentication) request.getAttribute(AUTHENTICATION_REQUEST_ID);

        LOG.debug(String.format("/oidc/authorize %s %s", oidcSamlAuthentication.getDetails(), parameters));

        return doAuthorization(parameters, oidcSamlAuthentication, request, false, false);
    }

    @PostMapping(value = "/oidc/consent", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ModelAndView consent(@RequestParam Map<String, String> body,
                                Authentication authentication,
                                HttpServletRequest request) throws ParseException, JOSEException, IOException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, BadJOSEException, java.text.ParseException, URISyntaxException {
        LOG.debug(String.format("/oidc/consent %s %s", authentication.getDetails(), body));

        LinkedMultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.setAll(body);
        return this.doAuthorization(parameters, (OidcSamlAuthentication) authentication, request, false, true);
    }

    private ModelAndView doAuthorization(MultiValueMap<String, String> parameters,
                                         OidcSamlAuthentication samlAuthentication,
                                         HttpServletRequest request,
                                         boolean consentRequired,
                                         boolean createConsent) throws ParseException, CertificateException, JOSEException, IOException, BadJOSEException, java.text.ParseException, URISyntaxException, NoSuchProviderException, NoSuchAlgorithmException {
        AuthorizationRequest authenticationRequest = AuthorizationRequest.parse(parameters);

        Scope scope = authenticationRequest.getScope();
        boolean isOpenIdClient = scope != null && isOpenIDRequest(scope.toStringList());

        OpenIDClient client = openIDClientRepository.findByClientId(authenticationRequest.getClientID().getValue());
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
        String redirectURI = validateRedirectionURI(authenticationRequest, client).getRedirectURI();

        List<String> scopes = validateScopes(authenticationRequest, client);
        ResponseType responseType = validateGrantType(authenticationRequest, client);

        User user = samlAuthentication.getUser();
        MDCContext.mdcContext(user);

        Prompt prompt = authenticationRequest.getPrompt();
        boolean consentFromPrompt = prompt != null && prompt.toStringList().contains("consent");

        if (consentRequired && (consentFromPrompt || client.isConsentRequired())) {
            Optional<UserConsent> userConsentOptional = this.userConsentRepository.findUserConsentBySub(user.getSub());
            boolean userConsentRequired = consentFromPrompt || userConsentOptional
                    .map(userConsent -> userConsent.renewConsentRequired(user, scopes))
                    .orElse(true);

            if (userConsentRequired) {
                LOG.debug("Asking for consent for User " + user + " and scopes " + scopes);
                return doConsent(parameters, client, scopes, user);
            }
        }
        if (createConsent) {
            createConsent(scopes, user, client);
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

    private void createConsent(List<String> scopes, User user, OpenIDClient openIDClient) {
        LOG.info("Creating consent for User " + user + " and scopes " + scopes);
        UserConsent userConsent = userConsentRepository.findUserConsentBySub(user.getSub())
                .map(uc -> uc.updateHash(user, scopes)).orElse(new UserConsent(user, scopes, openIDClient));

        userConsentRepository.save(userConsent);
    }

    private ModelAndView doConsent(MultiValueMap<String, String> parameters, OpenIDClient client, List<String> scopes, User user) {
        Map<String, Object> body = new HashMap<>();
        body.put("parameters", parameters.entrySet().stream().collect(Collectors.toMap(
                entry -> entry.getKey(),
                entry -> entry.getValue().get(0)
        )));
        String authenticatingAuthority = user.getAuthenticatingAuthority();
        body.put("scopes", client.getScopes().stream().filter(scope -> scopes.contains(scope.getName())).collect(toList()));
        body.put("client", client.getName());
        List<String> allowedResourceServers = client.getAllowedResourceServers();
        List<OpenIDClient> resourceServers = this.openIDClientRepository.findByClientIdIn(allowedResourceServers);
        Map<String, String> audiences = allowedResourceServers.stream().collect(Collectors.toMap(
                name -> name,
                name -> resourceServers.stream().filter(rs -> rs.getClientId().equals(name)).findFirst().map(OpenIDClient::getName).orElse(name)
        ));
        body.put("audiences", audiences);
        Map<String, Object> attributes = user.getAttributes();
        Map<String, String> claims = attributes.keySet()
                .stream().collect(toMap(key -> key, key -> attributeValueForConsent(attributes.get(key))));
        body.put("claims", claims);
        body.put("email", attributes.get("email"));
        return new ModelAndView("consent", body);
    }

    @SuppressWarnings("unchecked")
    private String attributeValueForConsent(Object object) {
        if (object == null) {
            return "";
        }
        if (object instanceof Collection) {
            return ((Collection) object).stream().collect(Collectors.joining(", ")).toString();
        }
        return object.toString();
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
        EncryptedTokenValue encryptedAccessToken = tokenGenerator.generateAccessTokenWithEmbeddedUserInfo(user, client);
        String accessTokenValue = encryptedAccessToken.getValue();
        if (responseType.contains(ResponseType.Value.TOKEN.getValue()) || !isOpenIDRequest(authorizationRequest)) {
            String unspecifiedUrnHash = KeyGenerator.oneWayHash(user.getUnspecifiedNameId(), this.salt);
            AccessToken accessToken = new AccessToken(accessTokenValue, user.getSub(), client.getClientId(), scopes,
                    encryptedAccessToken.getKeyId(), accessTokenValidity(client), false, null, unspecifiedUrnHash);
            accessTokenRepository.insert(accessToken);
            result.put("access_token", accessTokenValue);
            result.put("token_type", "Bearer");
        }
        if (responseType.contains(ResponseType.Value.CODE.getValue())) {
            AuthorizationCode authorizationCode = createAndSaveAuthorizationCode(authorizationRequest, client, user);
            result.put("code", authorizationCode.getCode());
        }
        if (responseType.contains(OIDCResponseTypeValue.ID_TOKEN.getValue()) && isOpenIDRequest(scopes) && isOpenIDRequest(authorizationRequest)) {
            AuthenticationRequest authenticationRequest = (AuthenticationRequest) authorizationRequest;
            List<String> claims = getClaims(authorizationRequest);
            String idToken = tokenGenerator.generateIDTokenForAuthorizationEndpoint(
                    user, client, authenticationRequest.getNonce(), responseType, accessTokenValue, claims,
                    Optional.ofNullable((String) result.get("code")), state);
            result.put("id_token", idToken);
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

    public static ProvidedRedirectURI validateRedirectionURI(AuthorizationRequest authenticationRequest, OpenIDClient client) throws UnsupportedEncodingException {
        URI redirectionURI = authenticationRequest.getRedirectionURI();
        List<String> registeredRedirectUrls = client.getRedirectUrls();
        if (redirectionURI == null) {
            return registeredRedirectUrls.stream().findFirst().map(s -> new ProvidedRedirectURI(s, false))
                    .orElseThrow(() ->
                            new IllegalArgumentException(String.format("Client %s must have at least one redirectURI configured to use the Authorization flow",
                                    client.getClientId())));
        }

        String redirectURI = URLDecoder.decode(redirectionURI.toString(), "UTF-8");
        Optional<ProvidedRedirectURI> optionalProvidedRedirectURI = registeredRedirectUrls.stream()
                .map(url -> new ProvidedRedirectURI(url, true))
                .filter(providedRedirectURI -> providedRedirectURI.equalsIgnorePort(redirectURI))
                .findFirst();
        if (!optionalProvidedRedirectURI.isPresent()) {
            throw new RedirectMismatchException(
                    String.format("Client %s with registered redirect URI's %s requested authorization with redirectURI %s",
                            client.getClientId(), registeredRedirectUrls, redirectURI));
        }
        return optionalProvidedRedirectURI.get();
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

    public static String validatePrompt(HttpServletRequest request) throws ParseException {
        String promptValue = request.getParameter("prompt");
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

    public static List<String> validateScopes(AuthorizationRequest authorizationRequest, OpenIDClient client) {
        Scope scope = authorizationRequest.getScope();
        List<String> requestedScopes = scope != null ? scope.toStringList() : Collections.emptyList();
        List<String> scopes = client.getScopes().stream().map(oidc.model.Scope::getName).collect(toList());
        scopes.addAll(forFreeOpenIDScopes);
        if (!scopes.containsAll(requestedScopes)) {
            List<String> missingScopes = requestedScopes.stream().filter(s -> !scopes.contains(s)).collect(toList());
            throw new InvalidScopeException(
                    String.format("Scope(s) %s are not allowed for %s. Allowed scopes: %s",
                            missingScopes, client.getClientId(), client.getScopes()));
        }
        return requestedScopes;
    }
}
