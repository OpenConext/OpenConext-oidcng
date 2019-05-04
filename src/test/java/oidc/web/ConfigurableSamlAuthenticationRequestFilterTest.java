package oidc.web;

import com.nimbusds.oauth2.sdk.GrantType;
import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.*;

@ActiveProfiles(profiles = {"prod"}, inheritProfiles = false)
public class ConfigurableSamlAuthenticationRequestFilterTest extends AbstractIntegrationTest {

    @Test
    public void doFilterInternal() throws UnsupportedEncodingException {
        String clientId = "http://mock-sp";
        Response response = given().redirects().follow(false)
                .when()
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", "http://localhost:8091/redirect")
                .get("oidc/authorize");
        String location = response.getHeader("Location");
        String relayState = UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("RelayState");

        assertEquals(clientId, URLDecoder.decode(relayState, Charset.defaultCharset().toString()));
    }
}