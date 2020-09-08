package oidc.web;

import com.nimbusds.jwt.SignedJWT;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import oidc.AbstractIntegrationTest;
import oidc.model.OpenIDClient;
import oidc.secure.SignedJWTTest;
import oidc.user.SamlTest;
import org.junit.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.w3c.dom.NodeList;

import java.net.URLDecoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

@ActiveProfiles(profiles = {"test"}, inheritProfiles = false)
public class ConfigurableSamlAuthenticationRequestFilterTest extends AbstractIntegrationTest implements SamlTest, SignedJWTTest {

    @Test
    public void filterInternalWithForcedAuth() throws Exception {
        OpenIDClient client = openIDClient("mock-sp");
        String keyID = getCertificateKeyID(client);
        String requestSignedJWT = signedJWT(client.getClientId(), keyID, client.getRedirectUrls().get(0)).serialize();
        AuthenticationRequest authenticationRequest
                = (AuthenticationRequest) doFilterInternal("mock-sp", "login", null, requestSignedJWT, true, "http://localhost:8091/redirect", "code", "query", null, true);
        assertEquals(true, authenticationRequest.isForceAuth());
    }

    @Test
    public void filterInternalWithLoa() throws Exception {
        OpenIDClient client = openIDClient("mock-sp");
        String keyID = getCertificateKeyID(client);
        String requestSignedJWT = signedJWT(client.getClientId(), keyID, client.getRedirectUrls().get(0)).serialize();
        AuthenticationRequest authenticationRequest
                = (AuthenticationRequest) doFilterInternal("mock-sp", null, "loa", requestSignedJWT, true, "http://localhost:8091/redirect", "code", "query", null, true);
        assertEquals("loa1,loa2,loa3", authenticationRequest.getAuthenticationContextClassReferences().stream().map(cr -> cr.getValue()).collect(Collectors.joining(",")));
    }

    @Test
    public void filterInternal() throws Exception {
        AuthenticationRequest authenticationRequest
                = (AuthenticationRequest) doFilterInternal("mock-sp", null, "loa", null, false, "http://localhost:8091/redirect", "code", "query", null, true);
        assertEquals("loa", authenticationRequest.getAuthenticationContextClassReferences().stream().map(cr -> cr.getValue()).collect(Collectors.joining(",")));
    }

    @Test
    public void filterInternalWithLoginHint() throws Exception {
        AuthenticationRequest authenticationRequest = (AuthenticationRequest) doFilterInternal("mock-sp", null, null, null,
                false, "http://localhost:8091/redirect", "code", "query", "entityID1, entityID2", true);
        assertEquals(2, authenticationRequest.getScoping().getIdpList().size());
    }

    @Test
    public void filterInternalPromptNoneError() throws Exception {
        filterInternalInvalidRequest("none", "interaction_required",
                "http://localhost:8091/redirect", "code", "query", "mock-sp");
    }

    @Test
    public void filterInternalPromptSelectAccountError() throws Exception {
        filterInternalInvalidRequest("select_account", "account_selection_required",
                "http://localhost:8091/redirect", "code", "query", "mock-sp");
    }

    @Test
    public void filterInternalInvalidGrantTypeFormPostError() throws Exception {
        filterInternalInvalidRequest(null, "unauthorized_client",
                "http://localhost:8091/redirect", "token", "form_post", "mock-rp");
    }

    private void filterInternalInvalidRequest(String prompt, String expectedMsg, String redirectUri,
                                              String responseType, String responseMode, String clientId) throws Exception {
        Map map = (Map) doFilterInternal(clientId, prompt, null, null, false, redirectUri, responseType, responseMode, null, false);
        assertEquals(expectedMsg, map.get("error"));
        assertEquals("example", map.get("state"));
    }

    private Object doFilterInternal(String clientId, String prompt, String acrValue, String requestSignedJWT,
                                    boolean isForceAuth, String redirectUri, String responseType, String responseMode, String loginHint, boolean expectsAuthorizationCode)
            throws Exception {
        RequestSpecification when = given().redirects().follow(false).when();
        if (StringUtils.hasText(clientId)) {
            when.queryParam("client_id", clientId);
        }
        if (StringUtils.hasText(prompt)) {
            when.queryParam("prompt", prompt);
        }
        if (StringUtils.hasText(acrValue)) {
            when.queryParam("acr_values", acrValue);
        }
        if (StringUtils.hasText(loginHint)) {
            when.queryParam("login_hint", loginHint);
        }
        when.queryParam("response_type", responseType)
                .queryParam("scope", "openid")
                .queryParam("state", "example")
                .queryParam("response_mode", responseMode);

        if (StringUtils.hasText(requestSignedJWT)) {
            when.queryParam("request", requestSignedJWT);
        }
        Response response = when
                .queryParam("redirect_uri", redirectUri)
                .get("oidc/authorize");

        String location = response.getHeader("Location");
        if (location == null) {
            if ("form_post".equals(responseMode)) {
                NodeList nodeList = getNodeListFromFormPost(response);
                Map<String, String> form = new HashMap<>();
                form.put("state", nodeList.item(0).getAttributes().getNamedItem("value").getNodeValue());
                form.put("error", nodeList.item(1).getAttributes().getNamedItem("value").getNodeValue());
                if (expectsAuthorizationCode) {
                    throw new IllegalArgumentException("Expected AuthorizationCode, got " + form);
                }
                return form;
            }
            Map res = response.getBody().as(Map.class);
            if (expectsAuthorizationCode) {
                throw new IllegalArgumentException("Expected AuthorizationCode, got " + res);
            }
            return res;
        }
        if (location.contains("error")) {
            Map res = null;
            if (responseMode.equals("query")) {
                res = UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();
            }
            if (responseMode.equals("fragment")) {
                String fragment = UriComponentsBuilder.fromUriString(location).build().getFragment();
                res = fragmentToMap(fragment);
            }
            if (responseMode.equals("form_post")) {
                res = response.getBody().as(Map.class);
            }
            if (expectsAuthorizationCode) {
                throw new IllegalArgumentException("Expected AuthorizationCode, got " + res);
            }
            return res;
        }
        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUriString(location).build().getQueryParams();

        String relayState = queryParams.getFirst("RelayState");

        RelayState decodedRelayState = RelayState.from(URLDecoder.decode(relayState, "UTF-8"), objectMapper);
        assertEquals(clientId, decodedRelayState.getClientId());
        assertEquals(acrValue, decodedRelayState.getAcrValues());

        String samlRequest = URLDecoder.decode(queryParams.getFirst("SAMLRequest"), "UTF-8");
        AuthenticationRequest authenticationRequest = resolveFromEncodedXML(AuthenticationRequest.class, samlRequest);
        assertEquals(isForceAuth, authenticationRequest.isForceAuth());
        if (StringUtils.hasText(requestSignedJWT)) {
            String acrValues = (String) SignedJWT.parse(requestSignedJWT).getJWTClaimsSet().getClaim("acr_values");
            List<AuthenticationContextClassReference> classReferences = authenticationRequest.getAuthenticationContextClassReferences();
            String loas = String.join(" ", classReferences.stream().map(AuthenticationContextClassReference::getValue).collect(Collectors.toList()));
            assertEquals(acrValues, loas);
        }

        return authenticationRequest;
    }
}