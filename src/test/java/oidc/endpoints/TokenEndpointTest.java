package oidc.endpoints;

import com.nimbusds.oauth2.sdk.GrantType;
import oidc.AbstractIntegrationTest;
import org.junit.Test;

import static io.restassured.RestAssured.given;

public class TokenEndpointTest extends AbstractIntegrationTest {

    @Test
    public void token() {
        String code = doAuthorize();
        given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .auth()
                .preemptive()
                .basic("http@//mock-rp", "secret")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("code", code)
                .post("oidc/token")
                .then()
                .statusCode(200);
        //.body(nullValue());

    }
}