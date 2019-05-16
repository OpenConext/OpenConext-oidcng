package oidc.secure;

import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import org.junit.Test;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.*;

public class LoggingStrictHttpFirewallTest extends AbstractIntegrationTest {

    @Test
    public void request() {
        Response response = given()
                .when()
                .post("oidc//.//introspect");
        assertEquals(400, response.getStatusCode());

    }

}