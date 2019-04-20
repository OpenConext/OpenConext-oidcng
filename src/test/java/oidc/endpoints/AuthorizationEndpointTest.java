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

public class AuthorizationEndpointTest extends AbstractIntegrationTest {

    @Test
    public void authorize() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid profile");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", "http@//mock-rp");
        queryParams.put("redirect_uri", "http://localhost:8091/redirect");
        queryParams.put("state", "http://localhost:8091/state");

        Response response = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize");
        String location = response.getHeader("Location");
        Matcher matcher = Pattern.compile(
                "\\Qhttp://localhost:8091/redirect?code=\\E(.*)\\Q&state=http://localhost:8091/state\\E")
                .matcher(location);
        matcher.find();
        String code = matcher.group(1);
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