package oidc;

import org.junit.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_OK;
import static org.hamcrest.Matchers.equalTo;

public class ApplicationTest extends AbstractIntegrationTest {

    @Test
    public void health() {
        given()
                .when()
                .get("internal/health")
                .then()
                .statusCode(SC_OK)
                .body("status", equalTo("UP"));
    }

    @Test
    public void info() {
        given()
                .when()
                .get("internal/info")
                .as(Map.class);
    }
}