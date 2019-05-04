package oidc.endpoints;

import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import oidc.AbstractIntegrationTest;
import oidc.model.AccessToken;
import org.junit.Test;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

public class UserInfoEndpointTest extends AbstractIntegrationTest {

    @Test
    public void getUserInfo() {
        userInfo("GET");
        userInfoWithAuthorizationHeader();
    }

    @Test
    public void postUserInfo() {
        userInfo("POST");

    }

    @Test
    public void userInfoExpired() {
        String token = getAccessToken();
        expireAccessToken(token);

        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("access_token", token)
                .post("oidc/userinfo")
                .as(mapTypeRef);
        assertEquals("Access token expired", body.get("message"));
    }

    private void userInfo(String method) {
        String accessToken = getAccessToken();
        RequestSpecification header = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded");

        Response response = method.equals("POST") ? header
                .formParam("access_token", accessToken)
                .post("oidc/userinfo") :
                header.queryParams("access_token", accessToken).get("oidc/userinfo");
        assertResponse(response);
    }

    private void userInfoWithAuthorizationHeader() {
        String accessToken = getAccessToken();
        Response response = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .header("Authorization", "Bearer " + accessToken)
                .get("oidc/userinfo");
        assertResponse(response);
    }

    private String getAccessToken() {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);
        return (String) body.get("access_token");
    }

    private void assertResponse(Response response) {
        Map<String, Object> result = response.as(mapTypeRef);
        assertEquals("john.doe@example.org", result.get("email"));
        assertEquals(true, result.containsKey("sub"));
    }
}