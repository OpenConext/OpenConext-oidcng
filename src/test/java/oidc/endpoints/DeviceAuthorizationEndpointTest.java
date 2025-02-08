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

public class DeviceAuthorizationEndpointTest extends AbstractIntegrationTest {

    @Test
    public void deviceAuthorization() {
        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("client_id", "mock-sp")
                .formParam("scope", "openid groups")
                .post("oidc/device_authorization")
                .as(mapTypeRef);
        assertEquals(900, (int) body.get("expires_in"));
        assertEquals(1, (int) body.get("interval"));

        String deviceCode = (String) body.get("device_code");
        assertEquals(deviceCode, UUID.fromString(deviceCode).toString());

        String verificationURI = "http://localhost:8080/oidc/verify";
        assertEquals(verificationURI, body.get("verification_uri"));
        String userCode = (String) body.get("user_code");
        assertEquals(body.get("verification_uri_complete"), verificationURI + "?user_code=" + userCode);
        //See QRGeneratorTest#qrCode for qr_code validation
        assertNotNull(body.get("qr_code"));

        DeviceAuthorization deviceAuthorization = mongoTemplate
                .findOne(Query.query(Criteria.where("deviceCode").is(deviceCode)), DeviceAuthorization.class);
        assertEquals(DeviceAuthorizationStatus.authorization_pending, deviceAuthorization.getStatus());
        assertNull(deviceAuthorization.getUserSub());

        DeviceAuthorization deviceAuthorizationByUserCode = mongoTemplate
                .findOne(Query.query(Criteria.where("userCode").is(userCode.replaceAll("-", ""))), DeviceAuthorization.class);
        assertEquals(deviceAuthorizationByUserCode.getId(), deviceAuthorization.getId());
    }

    @Test
    public void deviceAuthorizationInvalidClient() {
        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("client_id", "nope")
                .post("oidc/device_authorization")
                .as(mapTypeRef);
        assertEquals(401, (int) body.get("status"));
        assertEquals("unauthorized", body.get("error"));
    }

    @Test
    public void deviceAuthorizationInvalidGrant() {
        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("client_id", "mock-rp")
                .post("oidc/device_authorization")
                .as(mapTypeRef);
        assertEquals(401, (int) body.get("status"));
        assertEquals("unauthorized_client", body.get("error"));
        assertEquals("Missing grant: urn:ietf:params:oauth:grant-type:device_code for clientId: mock-rp", body.get("error_description"));
    }

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
        String userCode = (String) body.get("user_code");

        InputStream verificationInputStream = given()
                .when()
                .get("oidc/verify")
                .body()
                .asInputStream();
        String verificationView = IOUtils.toString(verificationInputStream, Charset.defaultCharset());
        assertTrue(verificationView.contains("Verify code and proceed to login"));

        //Now post the correct userCode
        Response response = given()
                .redirects().follow(false)
                .when()
                .formParam("userCode", userCode)
                .post("oidc/verify");
        response
                .then()
                .statusCode(302);

        String strippedUserCode = userCode.replaceAll("-", "");
        DeviceAuthorization deviceAuthorization = mongoTemplate
                .findOne(Query.query(Criteria.where("userCode").is(strippedUserCode)), DeviceAuthorization.class);

        String location = response.getHeader("Location");
        String authorizeLocation = String.format("oidc/device_authorize?client_id=mock-sp&user_code=%s&state=%s",
                strippedUserCode,
                deviceAuthorization.getState()
        );
        assertTrue(location.contains("oidc/device_authorize"));

        InputStream authorizationInputStream = given()
                .when()
                .get(authorizeLocation)
                .body()
                .asInputStream();
        String authorizationView = IOUtils.toString(authorizationInputStream, Charset.defaultCharset());
        assertTrue(authorizationView.contains("You have successfully authenticated"));

        DeviceAuthorization deviceAuthorizationFromDB = mongoTemplate
                .findOne(Query.query(Criteria.where("userCode").is(strippedUserCode)), DeviceAuthorization.class);
        assertEquals(DeviceAuthorizationStatus.success, deviceAuthorizationFromDB.getStatus());
    }

    @SneakyThrows
    @Test
    public void deviceAuthorizationCompleteURI() {
        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("client_id", "mock-sp")
                .formParam("scope", "openid groups")
                .post("oidc/device_authorization")
                .as(mapTypeRef);
        String userCode = (String) body.get("user_code");

        InputStream verificationInputStream = given()
                .when()
                .queryParam("user_code", userCode)
                .get("oidc/verify")
                .body()
                .asInputStream();
        String verificationView = IOUtils.toString(verificationInputStream, Charset.defaultCharset());
        assertTrue(verificationView.contains("Confirm code from device OpenConext Mock SP and proceed to login"));
    }

    @SneakyThrows
    @Test
    public void deviceAuthorizationRateLimit() {
        given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("client_id", "mock-sp")
                .formParam("scope", String.join(",", List.of("openid", "groups")))
                .post("oidc/device_authorization");

        CookieFilter cookieFilter = new CookieFilter();
        InputStream verificationInputStream = given()
                .filter(cookieFilter)
                .when()
                .formParam("userCode", "nope")
                .post("oidc/verify")
                .body()
                .asInputStream();
        String verificationView = IOUtils.toString(verificationInputStream, Charset.defaultCharset());
        assertTrue(verificationView.contains("Wrong code. Number of attempts left 2"));

        IntStream.range(0, 2).forEach(i -> {
            given()
                    .filter(cookieFilter)
                    .when()
                    .formParam("userCode", "nope")
                    .post("oidc/verify")
                    .then()
                    .statusCode(200);
        });

        InputStream rateLimitInputStream = given()
                .filter(cookieFilter)
                .when()
                .formParam("userCode", "nope")
                .post("oidc/verify")
                .body()
                .asInputStream();
        String rateLimitView = IOUtils.toString(rateLimitInputStream, Charset.defaultCharset());
        assertTrue(rateLimitView.contains("Number of attempts exceeded"));
    }

    @Test
    public void deviceAuthorizationInvalidScope() {
        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("client_id", "mock-sp")
                .formParam("scope", String.join(",", List.of("not-granted")))
                .post("oidc/device_authorization")
                .as(mapTypeRef);
        assertEquals(401, (int) body.get("status"));
        assertEquals("invalid_scope", body.get("error"));
    }

    @Test
    public void generateUserCode() {
        String userCode = new DeviceAuthorizationEndpoint(null, null, null, null)
                .generateUserCode();
        assertTrue(Pattern.compile("[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}").matcher(userCode).matches());
    }

    @SneakyThrows
    @Test
    public void deviceTokenRequest() {
        Map<String, Object> tokenRequestResponse = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("client_id", "mock-sp")
                .formParam("scope", "openid groups")
                .post("oidc/device_authorization")
                .as(mapTypeRef);
        String deviceCode = (String) tokenRequestResponse.get("device_code");
        String userCode = (String) tokenRequestResponse.get("user_code");

        Map<String, Object> pendingTokenResult = given()
                .when()
                .formParam("grant_type", GrantType.DEVICE_CODE.getValue())
                .formParam("device_code", deviceCode)
                .formParam("client_id", "mock-sp")
                .accept(ContentType.JSON)
                .post("oidc/token")
                .as(mapTypeRef);

        assertEquals(400, (int) pendingTokenResult.get("status"));
        assertEquals("authorization_pending", pendingTokenResult.get("error"));

        DeviceAuthorization deviceAuthorization = mongoTemplate
                .findOne(Query.query(Criteria.where("deviceCode").is(deviceCode)), DeviceAuthorization.class);
        deviceAuthorization.setLastLookup(Instant.now().plus(5, ChronoUnit.MINUTES));
        mongoTemplate.save(deviceAuthorization, "device_authorizations");

        Map<String, Object> slowDownTokenResult = given()
                .when()
                .formParam("grant_type", GrantType.DEVICE_CODE.getValue())
                .formParam("device_code", deviceCode)
                .formParam("client_id", "mock-sp")
                .accept(ContentType.JSON)
                .post("oidc/token")
                .as(mapTypeRef);

        assertEquals(400, (int) slowDownTokenResult.get("status"));
        assertEquals("slow_down", slowDownTokenResult.get("error"));

        deviceAuthorization = mongoTemplate
                .findOne(Query.query(Criteria.where("deviceCode").is(deviceCode)), DeviceAuthorization.class);
        //Mock - see FakeSamlAuthenticationFilter#authorizeEndpoints - the successful user authentication
        String authorizeLocation = String.format("oidc/device_authorize?client_id=mock-sp&user_code=%s&state=%s",
                userCode,
                deviceAuthorization.getState());
        given()
                .when()
                .get(authorizeLocation)
                .then()
                .statusCode(200);

        deviceAuthorization = mongoTemplate
                .findOne(Query.query(Criteria.where("deviceCode").is(deviceCode)), DeviceAuthorization.class);
        assertEquals(DeviceAuthorizationStatus.success, deviceAuthorization.getStatus());

        Map<String, Object> successTokenResult = given()
                .when()
                .formParam("grant_type", GrantType.DEVICE_CODE.getValue())
                .formParam("device_code", deviceCode)
                .formParam("client_id", "mock-sp")
                .accept(ContentType.JSON)
                .post("oidc/token")
                .as(mapTypeRef);

        String accessToken = (String) successTokenResult.get("access_token");
        JWTClaimsSet accessTokenClaimsSet = processToken(accessToken, port);
        assertEquals("openid groups", accessTokenClaimsSet.getClaim("scope"));

        String idToken = (String) successTokenResult.get("id_token");
        JWTClaimsSet idTokenClaimsSet = verifySignedJWT(idToken, port);
        assertEquals("mock-sp", ((List<String>) idTokenClaimsSet.getClaim("aud")).get(0));

        deviceAuthorization = mongoTemplate
                .findOne(Query.query(Criteria.where("deviceCode").is(deviceCode)), DeviceAuthorization.class);
        assertNull(deviceAuthorization);
    }

    @SneakyThrows
    @Test
    public void deviceTokenRequestWrongDeviceCode() {
        Map<String, Object> pendingTokenResult = given()
                .when()
                .formParam("grant_type", GrantType.DEVICE_CODE.getValue())
                .formParam("device_code", "nope")
                .formParam("client_id", "mock-sp")
                .accept(ContentType.JSON)
                .post("oidc/token")
                .as(mapTypeRef);

        assertEquals(400, (int) pendingTokenResult.get("status"));
        assertEquals("expired_token", pendingTokenResult.get("error"));
    }

    @SneakyThrows
    @Test
    public void deviceTokenRequestWrongClientID() {
        Map<String, Object> tokenRequestResponse = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("client_id", "mock-sp")
                .formParam("scope", "openid groups")
                .post("oidc/device_authorization")
                .as(mapTypeRef);
        String deviceCode = (String) tokenRequestResponse.get("device_code");

        Map<String, Object> pendingTokenResult = given()
                .when()
                .formParam("grant_type", GrantType.DEVICE_CODE.getValue())
                .formParam("device_code", deviceCode)
                .formParam("client_id", "mock-rp")
                .accept(ContentType.JSON)
                .post("oidc/token")
                .as(mapTypeRef);

        assertEquals(400, (int) pendingTokenResult.get("status"));
        assertEquals("access_denied", pendingTokenResult.get("error"));
    }
}