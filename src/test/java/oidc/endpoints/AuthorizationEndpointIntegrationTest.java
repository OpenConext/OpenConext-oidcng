package oidc.endpoints;

import com.nimbusds.jwt.PlainJWT;
import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import oidc.model.OpenIDClient;
import oidc.secure.SignedJWTTest;
import org.junit.Test;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@ActiveProfiles(value = "prod", inheritProfiles = false)
public class AuthorizationEndpointIntegrationTest extends AbstractIntegrationTest implements SignedJWTTest {

    @Test
    public void validationScope() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid nope");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", "mock-sp");
        queryParams.put("state", "example");
        queryParams.put("redirect_uri", URLEncoder.encode("http://localhost:3006/redirect", StandardCharsets.UTF_8));

        Response response = doAuthorize(queryParams);
        response
                .then()
                .statusCode(302)
                .body(containsString("not allowed"))
                .header("Location", containsString("example"));
    }

    @Test
    public void unSignedJwtAuthorization() throws Exception {
        OpenIDClient client = openIDClient("mock-sp");
        PlainJWT plainJWT = plainJWT(client.getClientId(), client.getRedirectUrls().get(0));

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", "mock-sp");
        queryParams.put("state", "openid");
        queryParams.put("redirect_uri", URLEncoder.encode("http://localhost:3006/redirect", StandardCharsets.UTF_8));
        queryParams.put("request", plainJWT.serialize());

        Response response = doAuthorize(queryParams);
        response
                .then()
                .statusCode(302);
        String location = response.getHeader("Location");
        assertEquals(302, response.getStatusCode());
        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(location).build().getQueryParams();
        assertEquals("request_not_supported", params.getFirst("error"));
    }

    @Test
    public void noResponseType() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid");
        queryParams.put("client_id", "mock-sp");
        queryParams.put("redirect_uri", URLEncoder.encode("http://localhost:3006/redirect", StandardCharsets.UTF_8));

        Response response = doAuthorize(queryParams);
        String location = response.getHeader("Location");
        assertEquals(302, response.getStatusCode());
        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(location).build().getQueryParams();
        assertEquals(params.getFirst("error"), "invalid_request");

        //'error_description' field MUST NOT include characters outside the set %09-0A (Tab and LF) / %x0D (CR) / %x20-21 / %x23-5B / %x5D-7E
        assertEquals("Missing+response_type+parameter", params.getFirst("error_description"));
    }

    private Response doAuthorize(Map<String, String> queryParams) {
        Response response = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize");
        Map<String, String> cookies = response.getCookies();

        String location = response.getHeader("Location");
        assertTrue(location.contains("/saml2/authenticate/oidcng"));

        //strip the url
        String strippedLocation = location.substring(location.indexOf("saml2/authenticate/oidcng"));
        response = given().redirects().follow(false)
                .cookies(cookies)
                .when()
                .get(strippedLocation);
        return response;
    }

}
