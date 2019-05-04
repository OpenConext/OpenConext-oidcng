package oidc;

import org.junit.Test;

import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_OK;
import static org.hamcrest.Matchers.equalTo;

public class ApplicationTest extends AbstractIntegrationTest {

    @Test
    public void health() throws Exception {
        given()
                .when()
                .get("actuator/health")
                .then()
                .statusCode(SC_OK)
                .body("status", equalTo("UP"));
    }

}