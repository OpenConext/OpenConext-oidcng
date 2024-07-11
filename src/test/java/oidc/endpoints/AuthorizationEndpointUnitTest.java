package oidc.endpoints;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.Prompt;
import oidc.exceptions.InvalidGrantException;
import oidc.exceptions.InvalidScopeException;
import oidc.exceptions.RedirectMismatchException;
import oidc.exceptions.UnsupportedPromptValueException;
import oidc.model.OpenIDClient;
import oidc.model.ProvidedRedirectURI;
import oidc.repository.OpenIDClientRepository;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.*;
import java.util.stream.Collectors;

import static java.nio.charset.Charset.defaultCharset;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthorizationEndpointUnitTest {

    @Test
    public void validateGrantType() throws IOException, ParseException {
        doValidateGrantType("authorization_code", "code");
    }

    @Test(expected = InvalidGrantException.class)
    public void validateGrantTypeNotConfiguredImplicit() throws IOException, ParseException {
        doValidateGrantType("authorization_code", "token");
    }

    @Test(expected = InvalidGrantException.class)
    public void validateGrantTypeNotConfiguredCode() throws IOException, ParseException {
        doValidateGrantType("implicit", "code");
    }

    @Test
    public void validateScope() {
        doValidateScope("open_id", "open_id", "authorization_code");
    }

    @Test
    public void validateScopeOfflineAccess() {
        doValidateScope("open_id", "open_id, offline_access", "authorization_code", "refresh_token");
    }

    @Test(expected = InvalidScopeException.class)
    public void validateScopeOfflineAccessNorefreshToken() {
        doValidateScope("open_id", "open_id, offline_access", "authorization_code");
    }

    @Test(expected = InvalidScopeException.class)
    public void doValidateScopeInvalid() {
        doValidateScope("nope", "some", "authorization_code");
    }

    @Test
    public void validateRedirectUri() throws IOException, ParseException {
        doValidateRedirectionUri("https://redirect", "https://redirect");
    }

    @Test
    public void validateRedirectUriLocalhost() throws IOException, ParseException {
        doValidateRedirectionUri("http://localhost:3333", "http://localhost:8080");
    }

    @Test(expected = RedirectMismatchException.class)
    public void validateRedirectUriNonLocalhost() throws IOException, ParseException {
        doValidateRedirectionUri("http://domain.net:3333", "http://domain.net:8080");
    }

    @Test
    public void validateRedirectUriDefault() throws IOException, ParseException {
        doValidateRedirectionUri("https://redirect", null);
    }

    @Test(expected = RedirectMismatchException.class)
    public void doValidateRedirectUriInvalid() throws IOException, ParseException {
        doValidateRedirectionUri("https://nope", "https://reedirect");
    }

    @Test
    public void doValidateRedirectUriQuery() throws IOException, ParseException {
        doValidateRedirectionUri("https://domain.net?key=val", "https://domain.net?key=val");
    }

    @Test(expected = IllegalArgumentException.class)
    public void doValidateRedirectUriIllegal() throws IOException, ParseException {
        doValidateRedirectionUri(null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void validatePrompt() {
        AuthorizationEndpoint.validatePrompt(new Prompt("nope"));
    }

    @Test(expected = UnsupportedPromptValueException.class)
    public void validatePromptInvalid() {
        AuthorizationEndpoint.validatePrompt(new Prompt("select_account"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void validateRedirectionUriQueryParams() throws IOException, ParseException {
        String requestRedirectUri = "http://domain.net?param=pickme";
        AuthorizationRequest authorizationRequest = authorizationRequest(new FluentMap<String, String>()
                .p("client_id", "http://oidc-rp")
                .p("response_type", "code")
                .p("redirect_uri", requestRedirectUri));
        OpenIDClient client = openIDClient("http://domain.net?param=first", "open_id", "authorization_code");
        client.getRedirectUrls().add("http://domain.net?param=pickme");
        ProvidedRedirectURI redirectUri = AuthorizationEndpoint.validateRedirectionURI(authorizationRequest.getRedirectionURI(), client);

        assertEquals(redirectUri.getRedirectURI(), requestRedirectUri);
    }

    @Test
    public void mismatchEncodingSpringVSDefaultEncoder() {
        String originalState = "{\"returnUrl\":\"\"}";
        String uri = "http://localhost?state=" + originalState;

        String stateEncoded = URLEncoder.encode(originalState, defaultCharset());
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri);
        String uriString = builder.toUriString();
        String expectedUri = "http://localhost?state=" + stateEncoded;

        assertEquals(expectedUri, "http://localhost?state=%7B%22returnUrl%22%3A%22%22%7D");
        assertEquals(uriString, "http://localhost?state=%7B%22returnUrl%22:%22%22%7D");
        assertNotEquals(expectedUri, uriString);
        // UriComponentsBuilder does not encode ":" in the query params
        String fixedUri = "http://localhost?" +
                uriString.substring(uriString.indexOf("?") + 1)
                        .replace(":", URLEncoder.encode(":"));
        assertEquals(expectedUri, fixedUri);
        //Main use case is that the decoded query params match
        String decodedExpectedURI = URLDecoder.decode(expectedUri, defaultCharset());
        String decodedURIString = URLDecoder.decode(uriString, defaultCharset());
        assertEquals(decodedExpectedURI, decodedURIString);

    }


    @SuppressWarnings("unchecked")
    private void doValidateGrantType(String clientGrantType, String requestResponseType) throws IOException, ParseException {
        AuthorizationRequest authorizationRequest = authorizationRequest(
                new FluentMap<String, String>().p("client_id", "http://oidc-rp").p("response_type", requestResponseType));
        OpenIDClient client = openIDClient("http://redirect", "scope", clientGrantType);
        ResponseType responseType = AuthorizationEndpoint.validateGrantType(authorizationRequest, client);

        assertTrue(responseType.impliesCodeFlow());
    }

    @SuppressWarnings("unchecked")
    private void doValidateScope(String clientScope, String requestResponseScope, String... grants) {
        OpenIDClient client = openIDClient("http://redirect", clientScope, grants);

        OpenIDClientRepository openIDClientRepository = mock(OpenIDClientRepository.class);
        when(openIDClientRepository.findByClientIdIn(null))
                .thenReturn(Collections.singletonList(client));
        Scope scope = Scope.parse(requestResponseScope);
        List<String> scopes = AuthorizationEndpoint.validateScopes(openIDClientRepository, scope, client);

        assertEquals(scope.toStringList(), scopes);
    }

    @SuppressWarnings("unchecked")
    private void doValidateRedirectionUri(String clientRedirectUri, String requestRedirectUri) throws IOException, ParseException {
        AuthorizationRequest authorizationRequest = authorizationRequest(
                new FluentMap<String, String>()
                        .p("client_id", "http://oidc-rp")
                        .p("response_type", "code")
                        .p("redirect_uri", requestRedirectUri));
        OpenIDClient client = openIDClient(clientRedirectUri, "open_id", "authorization_code");
        ProvidedRedirectURI redirectUri = AuthorizationEndpoint.validateRedirectionURI(authorizationRequest.getRedirectionURI(), client);

        assertEquals(redirectUri.getRedirectURI(), requestRedirectUri != null ? requestRedirectUri : clientRedirectUri);
    }

    private OpenIDClient openIDClient(String redirectUrl, String scope, String... grants) {
        ArrayList<String> redirectUrls = new ArrayList<>();
        if (StringUtils.hasText(redirectUrl)) {
            redirectUrls.add(redirectUrl);
        }
        List<oidc.model.Scope> scopes = Arrays.stream(scope.split(",")).map(s -> new oidc.model.Scope(s.trim())).collect(Collectors.toList());
        return new OpenIDClient("https://mock-rp",
                redirectUrls,
                scopes,
                Arrays.asList(grants));
    }

    private AuthorizationRequest authorizationRequest(Map<String, String> parameters) throws IOException, ParseException {
        parameters.put("client_id", "https://mock-rp");
        String queryString = parameters.entrySet().stream()
                .filter(p -> p.getValue() != null)
                .map(p -> String.format("%s=%s", p.getKey(), p.getValue()))
                .collect(Collectors.joining("&"));
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "http://localhost");
        request.setQueryString(queryString);
        return AuthorizationRequest.parse(ServletUtils.createHTTPRequest(request));
    }
}