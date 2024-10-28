package oidc.endpoints;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.GrantType;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import lombok.SneakyThrows;
import oidc.AbstractIntegrationTest;
import oidc.model.DeviceAuthorization;
import oidc.model.DeviceAuthorizationStatus;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
                .formParam("scope", String.join(",", List.of("openid", "groups")))
                .post("oidc/device_authorization")
                .as(mapTypeRef);
        assertEquals(404, body.get("status"));

    }


}