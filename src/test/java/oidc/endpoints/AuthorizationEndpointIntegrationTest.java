package oidc.endpoints;

import io.restassured.http.Headers;
import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.test.context.ActiveProfiles;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertTrue;

@ActiveProfiles(value = "prod", inheritProfiles = false)
public class AuthorizationEndpointIntegrationTest extends AbstractIntegrationTest {

    @Test
    public void validationScope() throws UnsupportedEncodingException {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid nope");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", "mock-sp");
        queryParams.put("state", "example");
        queryParams.put("redirect_uri", URLEncoder.encode("http://localhost:3006/redirect", "UTF-8"));

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
        given().redirects().follow(false)
                .cookies(cookies)
                .when()
                .get(strippedLocation)
                .then()
                .statusCode(302)
                .body(containsString("not allowed"))
                .header("Location", containsString("example"));
    }

}
