package oidc.api;

import io.restassured.RestAssured;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import static io.restassured.RestAssured.given;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"cron.node-cron-job-responsible=false", "token-api.enabled=false"})
@ActiveProfiles("prod")
public class TokenControllerFeatureDisabledTest {

    @LocalServerPort
    protected int port;


    @Before
    public void before() {
        RestAssured.port = port;
    }

    @Test
    public void getTokens403() {
        given()
                .when()
                .header("Content-type", "application/json")
                .auth()
                .preemptive()
                .basic("eduid", "secret")
                .queryParam("unspecifiedID", "urn:collab:person:eduid.nl:test")
                .get("tokens")
                .then()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

}