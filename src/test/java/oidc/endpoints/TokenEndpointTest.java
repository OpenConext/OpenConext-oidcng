package oidc.endpoints;

import com.nimbusds.oauth2.sdk.GrantType;
import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

public class TokenEndpointTest extends AbstractIntegrationTest {

    @Test
    @SuppressWarnings("unchecked")
    public void token() {
        String code = doAuthorize();
        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .auth()
                .preemptive()
                .basic("http@//mock-sp", "secret")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("code", code)
                .post("oidc/token")
                .as(Map.class);
        assertEquals(new Integer(5 * 60), body.get("expires_in"));
        //TODO http://localhost:8080/oidc/certs
        //https://connect2id.com/products/nimbus-jose-jwt/examples/validating-jwt-access-tokens
    }
}