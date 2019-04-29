package oidc.endpoints;

import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import oidc.AbstractIntegrationTest;
import org.junit.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.*;

public class UserInfoEndpointTest extends AbstractIntegrationTest {

    @Test
    public void getUserInfo() {
        userInfo("GET");
    }

    @Test
    public void postUserInfo() {
        userInfo("POST");
    }

    private void userInfo(String method) {
        String code = doAuthorize("http@//mock-sp");
        Map<String, Object> body = doToken(code);
        String accessToken = (String) body.get("access_token");
        RequestSpecification header = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .header("Authorization", "Bearer " + accessToken);

        Response response = method.equals("POST") ? header
                .formParam("token", accessToken)
                .post("oidc/userinfo") :
                header.queryParams("token", accessToken).get("oidc/userinfo");
        Map<String, Object> result = response.as(mapTypeRef);
        assertEquals("john.doe@example.org", result.get("email"));
        assertEquals(true, result.containsKey("sub"));

    }
}