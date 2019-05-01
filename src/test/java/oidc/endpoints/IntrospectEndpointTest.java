package oidc.endpoints;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import io.restassured.mapper.TypeRef;
import oidc.AbstractIntegrationTest;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.POST;
import static io.restassured.RestAssured.given;
import static org.junit.Assert.*;

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
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);
        Map<String, Object> result = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .auth()
                .preemptive()
                .basic("http@//mock-sp", "secret")
                .formParam("token", body.get("access_token"))
                .post("oidc/introspect")
                .as(mapTypeRef);
        assertEquals(true, result.get("active"));
    }
}