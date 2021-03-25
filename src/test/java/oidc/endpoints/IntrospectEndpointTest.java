package oidc.endpoints;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import oidc.model.AccessToken;
import org.bson.Document;
import org.junit.ClassRule;
import org.junit.Test;
import org.springframework.data.mongodb.core.query.BasicQuery;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.POST;
import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class IntrospectEndpointTest extends AbstractIntegrationTest {

    @ClassRule
    public static WireMockRule wireMockRule = new WireMockRule(8099);

    @Test
    //https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/265
    public void introspectContract() throws MalformedURLException, ParseException {
        HTTPRequest request = new HTTPRequest(POST, new URL("http://localhost:8080/introspect"));
        request.setContentType("application/x-www-form-urlencoded");
        request.setQuery("token=123456");
        //https://tools.ietf.org/html/rfc7662 is vague about the authorization requirements, but apparently this is ok
        TokenIntrospectionRequest.parse(request);
    }

    @Test
    public void introspection() throws IOException {
        Map<String, Object> result = doIntrospection("mock-sp", "secret");
        assertEquals(true, result.get("active"));
        assertTrue(result.containsKey("unspecified_id"));
        assertTrue(result.containsKey("email"));
    }

    @Test
    public void introspectionEduIdInvalidPseudonymisation() throws IOException {
        Map<String, String> res = new HashMap<>();
        res.put("eduid", "pseudoEduid");

        Map<String, Object> result = doIntrospectionWithEduidUser(res);
        assertEquals(false, result.get("active"));

    }

    @Test
    public void introspectionEduIdValidPseudonymisation() throws IOException {
        String eduPersonPrincipalName = "eduPersonPrincipalName";

        Map<String, String> res = new HashMap<>();
        res.put("eduid", "pseudoEduid");
        res.put("eduperson_principal_name", eduPersonPrincipalName);

        Map<String, Object> result = doIntrospectionWithEduidUser(res);
        assertEquals(true, result.get("active"));
        assertEquals(eduPersonPrincipalName, result.get("eduperson_principal_name"));
    }

    private Map<String, Object> doIntrospectionWithEduidUser(Map<String, String> eduIdAttributePseudonymisationResult) throws IOException {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid");
        queryParams.put("client_id", "mock-sp");
        queryParams.put("response_type", "code");
        queryParams.put("redirect_uri", openIDClient("mock-sp").getRedirectUrls().get(0));

        Response response = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize?user=eduid");

        String code = getCode(response);
        Map<String, Object> body = doToken(code, "mock-sp", "secret", GrantType.AUTHORIZATION_CODE);
        String accessToken = (String) body.get("access_token");

        stubFor(get(urlPathMatching("/attribute-manipulation")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(eduIdAttributePseudonymisationResult))));

        return callIntrospection("resource-server-playground-client", accessToken, "secret");
    }

    @Test
    public void introspectionWithDefaultRP() throws IOException {
        Map<String, Object> result = doIntrospection("resource-server-playground-client", "secret");
        assertEquals(true, result.get("active"));
        assertEquals("mock-sp", result.get("client_id"));
        assertFalse(result.containsKey("unspecified_id"));
        assertTrue(result.containsKey("email"));
    }

    @Test
    public void introspectionWithKeyRollover() throws IOException, GeneralSecurityException, java.text.ParseException {
        tokenGenerator.rolloverSigningKeys();

        String accessToken = getAccessToken();

        tokenGenerator.rolloverSigningKeys();

        Map<String, Object> result = callIntrospection("mock-sp", accessToken, "secret");
        assertEquals(true, result.get("active"));
    }


    @Test
    public void introspectionNotAllowedResourceServer() throws IOException {
        Response response = doAuthorize("mock-rp", "code", null, null, null);
        String code = getCode(response);
        Map<String, Object> results = doToken(code, "mock-rp", "secret", GrantType.AUTHORIZATION_CODE);

        results = callIntrospection("resource-server-playground-client", (String) results.get("access_token"), "secret");
        assertEquals("RP mock-rp is not allowed to use the API of resource server resource-server-playground-client. Allowed resource servers are []",
                results.get("error_description"));
    }

    @Test
    public void introspectionClientCredentials() throws IOException {
        Map<String, Object> body = doToken(null, "mock-sp", "secret", GrantType.CLIENT_CREDENTIALS);
        String accessToken = (String) body.get("access_token");
        Map<String, Object> result = callIntrospection("mock-sp", accessToken, "secret");
        assertEquals(true, result.get("active"));
        assertEquals("", result.get("scope"));
        assertEquals("mock-sp", result.get("sub"));
        assertFalse(result.containsKey("email"));
    }

    private List<String> scopeToSortedList(String scope) {
        List<String> strings = Scope.parse(scope).toStringList();
        strings.sort(Comparator.comparing(String::toString));
        return strings;
    }

    @Test
    public void introspectionWithExpiredAccessToken() throws IOException, java.text.ParseException {
        String accessToken = getAccessToken();
        expireAccessToken(accessToken);
        Map<String, Object> result = callIntrospection("mock-sp", accessToken, "secret");
        assertEquals(false, result.get("active"));
    }

    @Test
    public void introspectionWithDeletedAccessToken() throws IOException, java.text.ParseException {
        String accessToken = getAccessToken();
        String jwtid = SignedJWT.parse(accessToken).getJWTClaimsSet().getJWTID();
        mongoTemplate.remove(new BasicQuery(new Document("jwtId", jwtid)), AccessToken.class);
        Map<String, Object> result = callIntrospection("mock-sp", accessToken, "secret");
        assertEquals(false, result.get("active"));
    }

    @Test
    public void introspectionWithInvalidAccessToken() throws IOException {
        Map<String, Object> result = callIntrospection("mock-sp", "bogus", "secret");
        assertEquals(false, result.get("active"));
    }

    @Test
    public void introspectionBadCredentials() throws IOException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);
        Map<String, Object> result = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("token", body.get("access_token"))
                .post("oidc/introspect")
                .as(mapTypeRef);
        assertEquals("Invalid user / secret", result.get("error_description"));
    }

    @Test
    public void introspectionNoResourceServer() throws IOException {
        Map<String, Object> result = doIntrospection("mock-rp", "secret");
        assertEquals("Requires ResourceServer", result.get("error_description"));
    }

    @Test
    public void introspectionWrongSecret() throws IOException {
        Map<String, Object> result = doIntrospection("mock-sp", "nope");
        assertEquals("Invalid user / secret", result.get("error_description"));
    }

    private Map<String, Object> doIntrospection(String clientId, String secret) throws IOException {
        String accessToken = getAccessToken();
        return callIntrospection(clientId, accessToken, secret);
    }

    private String getAccessToken() throws IOException {
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