package oidc.web;

import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import oidc.AbstractIntegrationTest;
import oidc.user.SamlTest;
import org.junit.Test;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

@ActiveProfiles(profiles = {"prod"}, inheritProfiles = false)
public class ConfigurableSamlAuthenticationRequestFilterTest extends AbstractIntegrationTest implements SamlTest {

    @Test
    public void filterInternalWithForcedAuth() throws UnsupportedEncodingException {
        doFilterInternal( "http://mock-sp", "login");
    }

    @Test
    public void filterInternal() throws UnsupportedEncodingException {
        doFilterInternal( null, null);
    }

    private void doFilterInternal(String clientId, String prompt) throws UnsupportedEncodingException {
        RequestSpecification when = given().redirects().follow(false).when();
        if (StringUtils.hasText(clientId)) {
            when.queryParam("client_id", clientId);
        }
        if (StringUtils.hasText(prompt)) {
            when.queryParam("prompt", prompt);
        }
        Response response = when
                .queryParam("redirect_uri", "http://localhost:8091/redirect")
                .get("oidc/authorize");

        String location = response.getHeader("Location");
        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUriString(location).build().getQueryParams();
        String relayState = queryParams.getFirst("RelayState");

        String decodedRelayState = StringUtils.hasText(relayState) ? URLDecoder.decode(relayState, "UTF-8") : null;
        assertEquals(clientId, decodedRelayState);

        String samlRequest = URLDecoder.decode(queryParams.getFirst("SAMLRequest"), "UTF-8");
        AuthenticationRequest authenticationRequest = resolveFromEncodedXML(AuthenticationRequest.class, samlRequest);
        assertEquals("login".equals(prompt), authenticationRequest.isForceAuth());
    }
}