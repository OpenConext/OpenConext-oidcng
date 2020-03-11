package oidc.endpoints;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.oauth2.sdk.GrantType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import oidc.AbstractIntegrationTest;
import oidc.web.ErrorController;
import org.junit.Test;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

public class UserInfoEndpointTest extends AbstractIntegrationTest {

    @Test
    public void getUserInfo() throws IOException {
        userInfo("GET");
        userInfoWithAuthorizationHeader();
    }

    @Test
    public void postUserInfo() throws IOException {
        userInfo("POST");
    }

    @Test
    public void userInfoExpired() throws IOException {
        String token = getAccessToken();
        expireAccessToken(token);

        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("access_token", token)
                .post("oidc/userinfo")
                .as(mapTypeRef);
        assertEquals("invalid_token", body.get("error"));
        assertEquals("Access Token expired", body.get("error_description"));
    }

    @Test
    public void userInfoClientCredentials() throws IOException {
        Logger errorLogger = (Logger) LoggerFactory.getLogger(ErrorController.class);
        ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
        listAppender.start();

        errorLogger.addAppender(listAppender);

        String token = getClientCredentialsAccessToken();

        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("access_token", token)
                .post("oidc/userinfo")
                .as(mapTypeRef);
        assertEquals("UserEndpoint not allowed for Client Credentials", body.get("message"));

        assertEquals(1, listAppender.list.size());
    }

    @Test
    public void userInfoAccessTokenNotFound() {
        Logger errorLogger = (Logger) LoggerFactory.getLogger(ErrorController.class);
        ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
        listAppender.start();

        errorLogger.addAppender(listAppender);

        Response response = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .queryParams("access_token", "bogus").get("oidc/userinfo");

        int status = response.statusCode();
        assertEquals(401, status);

        Map map = response.body().as(Map.class);
        assertEquals("invalid_token", map.get("error"));
        assertEquals("Access Token not found", map.get("error_description"));

        assertEquals(0, listAppender.list.size());
    }


    private void userInfo(String method) throws IOException {
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

    private void userInfoWithAuthorizationHeader() throws IOException {
        String accessToken = getAccessToken();
        Response response = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .header("Authorization", "Bearer " + accessToken)
                .get("oidc/userinfo");
        assertResponse(response);
    }

    private String getAccessToken() throws IOException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);
        return (String) body.get("access_token");
    }

    private String getClientCredentialsAccessToken() throws IOException {
        Map<String, Object> body = doToken(null, "mock-sp", "secret", GrantType.CLIENT_CREDENTIALS);
        return (String) body.get("access_token");
    }

    private void assertResponse(Response response) {
        Map<String, Object> result = response.as(mapTypeRef);
        assertEquals("john.doe@example.org", result.get("email"));
        assertEquals(true, result.containsKey("sub"));
    }
}