package oidc;

import io.restassured.RestAssured;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_OK;
import static org.hamcrest.Matchers.equalTo;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ApplicationTest { // Do not inherit from AbstractIntegrationTest to verify access

    @LocalServerPort
    protected int port;

    @Before
    public void before() {
        RestAssured.port = port;
    }

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