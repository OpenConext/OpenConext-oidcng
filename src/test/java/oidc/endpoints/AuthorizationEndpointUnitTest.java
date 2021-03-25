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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
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
    public void validateScope() throws IOException, ParseException {
        doValidateScope("open_id", "open_id");
    }

    @Test(expected = InvalidScopeException.class)
    public void doValidateScopeInvalid() throws IOException, ParseException {
        doValidateScope("nope", "some");
    }

    @Test
    public void validateRedirectUri() throws IOException, ParseException {
        doValidateRedirectionUri("https://redirect", "https://redirect");
    }

    @Test
    public void validateRedirectUriDefault() throws IOException, ParseException {
        doValidateRedirectionUri("https://redirect", null);
    }

    @Test(expected = RedirectMismatchException.class)
    public void doValidateRedirectUriInvalid() throws IOException, ParseException {
        doValidateRedirectionUri("https://nope", "https://reedirect");
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

    @SuppressWarnings("unchecked")
    private void doValidateGrantType(String clientGrantType, String requestResponseType) throws IOException, ParseException {
        AuthorizationRequest authorizationRequest = authorizationRequest(
                new FluentMap<String, String>().p("client_id", "http://oidc-rp").p("response_type", requestResponseType));
        OpenIDClient client = openIDClient("http://redirect", "scope", clientGrantType);
        ResponseType responseType = AuthorizationEndpoint.validateGrantType(authorizationRequest, client);

        assertTrue(responseType.impliesCodeFlow());
    }

    @SuppressWarnings("unchecked")
    private void doValidateScope(String clientScope, String requestResponseScope) throws IOException, ParseException {
        AuthorizationRequest authorizationRequest = authorizationRequest(
                new FluentMap<String, String>()
                        .p("client_id", "http://oidc-rp")
                        .p("response_type", "code")
                        .p("scope", requestResponseScope));
        OpenIDClient client = openIDClient("http://redirect", clientScope, "authorization_code");

        OpenIDClientRepository openIDClientRepository = mock(OpenIDClientRepository.class);
        when(openIDClientRepository.findByClientIdIn(null)).thenReturn(Collections.singletonList(openIDClient("http://redirect", clientScope, "authorization_code")));

        List<String> scopes = AuthorizationEndpoint.validateScopes(openIDClientRepository, new Scope(requestResponseScope), client);

        assertEquals(singletonList(requestResponseScope), scopes);
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

    private OpenIDClient openIDClient(String redirectUrl, String scope, String grant) {
        return new OpenIDClient("https://mock-rp",
                StringUtils.hasText(redirectUrl) ? singletonList(redirectUrl) : new ArrayList<>(),
                singletonList(new oidc.model.Scope(scope)),
                singletonList(grant));
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