package oidc.endpoints;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import oidc.AbstractIntegrationTest;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.POST;
import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

public class IntrospectEndpointTest extends AbstractIntegrationTest {

    @Test
    //https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/265
    public void introspectContract() throws MalformedURLException, ParseException {
        HTTPRequest request = new HTTPRequest(POST, new URL("http://localhost:8080/introspect"));
        request.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        request.setQuery("token=123456");
        //https://tools.ietf.org/html/rfc7662 is vague about the authorization requirements, but apparently this is ok
        TokenIntrospectionRequest.parse(request);
    }

    @Test
    public void introspection() {
        Map<String, Object> result = doIntrospection("http@//mock-sp", "secret");
        assertEquals(true, result.get("active"));
    }

    @Test
    public void introspectionWithExpiredAccessToken() {
        String accessToken = getAccessToken();
        expireAccessToken(accessToken);
        Map<String, Object> result = callIntrospection("http@//mock-sp", accessToken, "secret");
        assertEquals(false, result.get("active"));
    }

    @Test
    public void introspectionBadCredentials() {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);
        Map<String, Object> result = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("token", body.get("access_token"))
                .post("oidc/introspect")
                .as(mapTypeRef);
        assertEquals("Invalid user / secret", result.get("details"));
    }

    @Test
    public void introspectionNoResourceServer() {
        Map<String, Object> result = doIntrospection("http@//mock-rp", "secret");
        assertEquals("Requires ResourceServer", result.get("details"));
    }

    @Test
    public void introspectionWrongSecret() {
        Map<String, Object> result = doIntrospection("http@//mock-sp", "nope");
        assertEquals("Invalid user / secret", result.get("details"));
    }

    private Map<String, Object> doIntrospection(String clientId, String secret) {
        String accessToken = getAccessToken();
        return callIntrospection(clientId, accessToken, secret);
    }

    private String getAccessToken() {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);
        return (String) body.get("access_token");
    }

    private Map<String, Object> callIntrospection(String clientId, String accessToken, String secret) {
        return given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .auth()
                .preemptive()
                .basic(clientId, secret)
                .formParam("token", accessToken)
                .post("oidc/introspect")
                .as(mapTypeRef);
    }
}