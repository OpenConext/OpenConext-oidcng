package oidc.endpoints;

import oidc.AbstractIntegrationTest;
import org.junit.Test;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.*;

public class FeedbackControllerTest extends AbstractIntegrationTest {

    @Test
    public void feedback() {
        given()
                .when()
                .get("feedback/no-session")
                .then()
                .statusCode(200);
    }
}