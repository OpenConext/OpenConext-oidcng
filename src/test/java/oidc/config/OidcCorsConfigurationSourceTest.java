package oidc.config;

import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.http.HttpHeaders;

import static io.restassured.RestAssured.given;

public class OidcCorsConfigurationSourceTest extends AbstractIntegrationTest {

    @Test
    public void corsConfiguration() {
        given().redirects().follow(false)
                .when()
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .options("oidc/authorize")
                .then()
                .statusCode(200)
                .header("Allow", "GET,HEAD,OPTIONS");


    }
}