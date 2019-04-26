package oidc.endpoints;

import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.restassured.RestAssured.given;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.*;

public class AuthorizationEndpointTest extends AbstractIntegrationTest {

    @Test
    public void authorize() {
        String code = doAuthorize();
        assertEquals(12, code.length());
    }

    @Test
    public void validation() {
        Map<String, String> queryParams = new HashMap<>();

        given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize")
                .then()
                .statusCode(400)
                .body(containsString("Missing \\\"client_id\\\" parameter"));
    }
}