package oidc.endpoints;

import com.nimbusds.oauth2.sdk.GrantType;
import lombok.SneakyThrows;
import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "cron.node-cron-job-responsible=false",
                "features.oidcng_device_flow=false"
        })
public class DeviceAuthorizationEndpointDisabledTest extends AbstractIntegrationTest {

    @SneakyThrows
    @Test
    public void deviceAuthorizationHappyFlow() {
        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("client_id", "mock-sp")
                .formParam("scope", "openid groups")
                .post("oidc/device_authorization")
                .as(mapTypeRef);
        assertEquals(404, body.get("status"));

    }


}