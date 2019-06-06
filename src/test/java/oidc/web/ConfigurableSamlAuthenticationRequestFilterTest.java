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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.List;
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
        doFilterInternal( "mock-sp", "login", requestSignedJWT);
    }

    @Test
    public void filterInternal() throws UnsupportedEncodingException, ParseException {
        doFilterInternal( null, null, null);
    }

    private void doFilterInternal(String clientId, String prompt, String requestSignedJWT) throws UnsupportedEncodingException, ParseException {
        RequestSpecification when = given().redirects().follow(false).when();
        if (StringUtils.hasText(clientId)) {
            when.queryParam("client_id", clientId);
        }
        if (StringUtils.hasText(prompt)) {
            when.queryParam("prompt", prompt);
        }
        if (StringUtils.hasText(requestSignedJWT)) {
            when.queryParam("request", requestSignedJWT)
                    .queryParam("response_type", "code")
                    .queryParam("scope", "openid");
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
        if (StringUtils.hasText(requestSignedJWT)) {
            String acrValues = (String) SignedJWT.parse(requestSignedJWT).getJWTClaimsSet().getClaim("acr_values");
            List<AuthenticationContextClassReference> classReferences = authenticationRequest.getAuthenticationContextClassReferences();
            String loas = String.join(" ", classReferences.stream().map(AuthenticationContextClassReference::getValue).collect(Collectors.toList()));
            assertEquals(acrValues, loas);
        }

    }
}