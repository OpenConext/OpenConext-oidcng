package oidc.config;

import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.http.HttpHeaders;

import java.util.HashMap;

import static io.restassured.RestAssured.given;

public class OidcCorsConfigurationSourceTest extends AbstractIntegrationTest {
    @Test
    public void corsConfiguration() {
        String allowdOrigin = "http://oidcng.test.openconext.nl";

        HashMap<String, Object> expectedHeaders = new HashMap<>();
        expectedHeaders.put("Access-Control-Allow-Origin", allowdOrigin);
        expectedHeaders.put("Access-Control-Allow-Methods", "GET");
        expectedHeaders.put("Access-Control-Allow-Credentials", "true");

        given().redirects().follow(false)
                .when()
                .header(HttpHeaders.ORIGIN, allowdOrigin)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET", "POST")
                .options("/oidc/authorize")
                .then()
                .statusCode(200)
                .headers(expectedHeaders);


    }
}