package oidc.web;

import com.nimbusds.jwt.SignedJWT;
import io.restassured.response.Response;
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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.text.ParseException;
import java.util.Collections;
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
        doFilterInternal("mock-sp", "login", null, requestSignedJWT, true);
    }

    @Test
    public void filterInternalWithLoa() throws Exception {
        OpenIDClient client = openIDClient("mock-sp");
        String keyID = getCertificateKeyID(client);
        String requestSignedJWT = signedJWT(client.getClientId(), keyID).serialize();
        doFilterInternal("mock-sp", null, "loa", requestSignedJWT, true);
    }

    @Test
    public void filterInternal() throws UnsupportedEncodingException, ParseException {
        doFilterInternal("mock-sp", null, null, null, false);
    }

    @Test
    public void filterInternalPromptNone() throws UnsupportedEncodingException, ParseException {
        filterInternalInvalidPrompt("none", "interaction_required");
    }

    @Test
    public void filterInternalPromptConsent() throws UnsupportedEncodingException, ParseException {
        filterInternalInvalidPrompt("consent", "consent_required");
    }

    @Test
    public void filterInternalPromptSelectAccount() throws UnsupportedEncodingException, ParseException {
        filterInternalInvalidPrompt("select_account", "account_selection_required");
    }

    @Test
    public void filterInternalPromptUnsupported() throws UnsupportedEncodingException, ParseException {
        filterInternalInvalidPrompt("unsupported", "Unsupported prompt unsupported");
    }

    private void filterInternalInvalidPrompt(String prompt, String expectedMsg) throws UnsupportedEncodingException, ParseException {
        Map map = doFilterInternal("mock-sp", prompt, null, null, false);
        assertEquals(expectedMsg, map.get("message"));
        assertEquals(400, map.get("status"));
    }

    private Map doFilterInternal(String clientId, String prompt, String acrValue, String requestSignedJWT, boolean isForceAuth) throws UnsupportedEncodingException, ParseException {
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
        when.queryParam("response_type", "code")
                .queryParam("scope", "openid");

        if (StringUtils.hasText(requestSignedJWT)) {
            when.queryParam("request", requestSignedJWT);
        }
        Response response = when
                .queryParam("redirect_uri", "http://localhost:8091/redirect")
                .get("oidc/authorize");

        String location = response.getHeader("Location");
        if (location == null) {
            return response.getBody().as(Map.class);
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