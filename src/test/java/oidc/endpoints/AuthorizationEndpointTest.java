package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import oidc.OidcEndpointTest;
import org.junit.Test;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.*;

public class AuthorizationEndpointTest extends AbstractIntegrationTest implements OidcEndpointTest {

    @Test
    public void authorize() {
        String code = doAuthorize();
        assertEquals(12, code.length());
    }

    @Test
    public void validationMissingParameter() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("redirect_uri", "http%3A%2F%2Flocalhost%3A8080");

        given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize")
                .then()
                .statusCode(302)
                .header("Location", "http://localhost:8080")
                .body(containsString("Missing \\\"client_id\\\" parameter"));
    }

    @Test
    public void validationScope() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid nope");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", "http@//mock-sp");
        queryParams.put("redirect_uri", "http%3A%2F%2Flocalhost%3A8080");

        given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize")
                .then()
                .statusCode(302)
                .header("Location", "http://localhost:8080")
                .body(containsString("not allowed"));
    }

    @Test
    public void implicitFlow() throws MalformedURLException, BadJOSEException, ParseException, JOSEException {
        String url = doAuthorize("http@//mock-sp", "id_token token", null, "nonce");
        String fragment = url.substring(url.indexOf("#") + 1);
        Map<String, String> fragmentParameters = Arrays.stream(fragment.split("&")).map(s -> s.split("=")).collect(Collectors.toMap(s -> s[0], s -> s[1]));
        String idToken = fragmentParameters.get("id_token");
        JWTClaimsSet claimsSet = processToken(idToken, port);
        assertEquals("nonce", claimsSet.getClaim("nonce"));
        assertNotNull(claimsSet.getClaim("at_hash"));
    }

}