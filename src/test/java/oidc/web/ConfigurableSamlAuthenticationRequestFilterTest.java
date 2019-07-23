package oidc.web;

import com.nimbusds.jwt.SignedJWT;
import io.restassured.response.Response;
import io.restassured.response.ResponseBody;
import io.restassured.specification.RequestSpecification;
import oidc.AbstractIntegrationTest;
import oidc.model.OpenIDClient;
import oidc.secure.SignedJWTTest;
import oidc.user.SamlTest;
import org.junit.Test;
import org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import java.io.IOException;
import java.net.URLDecoder;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

@ActiveProfiles(profiles = {"prod"}, inheritProfiles = false)
public class ConfigurableSamlAuthenticationRequestFilterTest extends AbstractIntegrationTest implements SamlTest, SignedJWTTest {

    @Test
    public void filterInternalWithForcedAuth() throws Exception {
        OpenIDClient client = openIDClient("mock-sp");
        String keyID = getCertificateKeyID(client);
        String requestSignedJWT = signedJWT(client.getClientId(), keyID).serialize();
        doFilterInternal("mock-sp", "login", null, requestSignedJWT, true, "http://localhost:8091/redirect", "code", "query");
    }

    @Test
    public void filterInternalWithLoa() throws Exception {
        OpenIDClient client = openIDClient("mock-sp");
        String keyID = getCertificateKeyID(client);
        String requestSignedJWT = signedJWT(client.getClientId(), keyID).serialize();
        doFilterInternal("mock-sp", null, "loa", requestSignedJWT, true, "http://localhost:8091/redirect", "code", "query");
    }

    @Test
    public void filterInternal() throws Exception {
        doFilterInternal("mock-sp", null, null, null, false, "http://localhost:8091/redirect", "code", "query");
    }

    @Test
    public void filterInternalPromptNone() throws Exception {
        filterInternalInvalidRequest("none", "interaction_required",
                "http://localhost:8091/redirect", "code", "query", "mock-sp");
    }

    @Test
    public void filterInternalPromptConsent() throws Exception {
        filterInternalInvalidRequest("consent", "consent_required",
                "http://localhost:8091/redirect", "code", "query", "mock-sp");
    }

    @Test
    public void filterInternalPromptSelectAccount() throws Exception {
        filterInternalInvalidRequest("select_account", "account_selection_required",
                "http://localhost:8091/redirect", "code", "query", "mock-sp");
    }

    @Test
    public void filterInternalPromptUnsupported() throws Exception {
        filterInternalInvalidRequest("unsupported", "invalid_request",
                "http://localhost:8091/redirect", "code", "query", "mock-sp");
    }

    @Test
    public void filterInternalInvalidGrantType() throws Exception {
        filterInternalInvalidRequest(null, "unauthorized_client",
                "http://localhost:8091/redirect", "token", "fragment", "mock-rp");
    }

    @Test
    public void filterInternalInvalidGrantTypeFormPost() throws Exception {
        filterInternalInvalidRequest(null, "unauthorized_client",
                "http://localhost:8091/redirect", "token", "form_post", "mock-rp");
    }

    private void filterInternalInvalidRequest(String prompt, String expectedMsg, String redirectUri,
                                              String responseType, String responseMode, String clientId) throws Exception {
        Map map = doFilterInternal(clientId, prompt, null, null, false, redirectUri, responseType, responseMode);
        assertEquals(expectedMsg, map.get("error"));
        assertEquals("example", map.get("state"));
    }

    private Map doFilterInternal(String clientId, String prompt, String acrValue, String requestSignedJWT,
                                 boolean isForceAuth, String redirectUri, String responseType, String responseMode)
            throws IOException, ParseException, ParserConfigurationException, SAXException, XPathExpressionException {
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
                return form;
            }
            return response.getBody().as(Map.class);
        }
        if (location.contains("error")) {
            if (responseMode.equals("query")) {
                return UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();
            }
            if (responseMode.equals("fragment")) {
                String fragment = UriComponentsBuilder.fromUriString(location).build().getFragment();

                return fragmentToMap(fragment);
            }
            if (responseMode.equals("form_post")) {
                ResponseBody body = response.getBody();
            }

        }
        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUriString(location).build().getQueryParams();

        String relayState = queryParams.getFirst("RelayState");

        String decodedRelayState = StringUtils.hasText(relayState) ? URLDecoder.decode(relayState, "UTF-8") : null;
        assertEquals(clientId, decodedRelayState);

        String samlRequest = URLDecoder.decode(queryParams.getFirst("SAMLRequest"), "UTF-8");
        AuthenticationRequest authenticationRequest = resolveFromEncodedXML(AuthenticationRequest.class, samlRequest);
        assertEquals(isForceAuth, authenticationRequest.isForceAuth());
        if (StringUtils.hasText(requestSignedJWT)) {
            String acrValues = (String) SignedJWT.parse(requestSignedJWT).getJWTClaimsSet().getClaim("acr_values");
            List<AuthenticationContextClassReference> classReferences = authenticationRequest.getAuthenticationContextClassReferences();
            String loas = String.join(" ", classReferences.stream().map(AuthenticationContextClassReference::getValue).collect(Collectors.toList()));
            assertEquals(acrValues, loas);
        }

        return Collections.emptyMap();
    }
}