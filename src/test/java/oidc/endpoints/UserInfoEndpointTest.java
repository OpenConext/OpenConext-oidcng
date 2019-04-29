package oidc.endpoints;

import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import oidc.AbstractIntegrationTest;
import org.junit.Test;

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
        String code = doAuthorize("http@//mock-sp");
        Map<String, Object> body = doToken(code);
        return (String) body.get("access_token");
    }

    private void assertResponse(Response response) {
        Map<String, Object> result = response.as(mapTypeRef);
        assertEquals("john.doe@example.org", result.get("email"));
        assertEquals(true, result.containsKey("sub"));
    }
}