package oidc.endpoints;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.oauth2.sdk.GrantType;
import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
        "cron.node-cron-job-responsible=false",
        "eduid.uri=http://localhost:8099/attribute-manipulation",
        "features.enforce-eduid-resource-server-linked-account=false"

    })
public class IntrospectEndpointDisabledEduIDEnforcementTest extends AbstractIntegrationTest {

    @ClassRule
    public static WireMockRule wireMockRule = new WireMockRule(8099);

    @Test
    public void introspectionEduIdEmptyPseudonymisation() throws IOException {
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
            .withBody(objectMapper.writeValueAsString(Map.of()))));
        Map<String, Object> results = given()
            .when()
            .header("Content-type", "application/x-www-form-urlencoded")
            .auth()
            .preemptive()
            .basic("resource-server-playground-client", "secret")
            .formParam("token", accessToken)
            .post("oidc/introspect")
            .as(mapTypeRef);
        //See src/main/resources/data/eduid.json
        assertEquals("3415570f-be91-4ba8-b9ba-e479d18094d5", results.get("eduid"));
    }

    @Test
    public void introspectionEduIdValidPseudonymisation() throws IOException {
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

        Map<Object, Object> pseudonymiseResults = Map.of("eduid", UUID.randomUUID().toString());
        stubFor(get(urlPathMatching("/attribute-manipulation")).willReturn(aResponse()
            .withHeader("Content-Type", "application/json")
            .withBody(objectMapper.writeValueAsString(pseudonymiseResults))));

        Map<String, Object> results = given()
            .when()
            .header("Content-type", "application/x-www-form-urlencoded")
            .auth()
            .preemptive()
            .basic("resource-server-playground-client", "secret")
            .formParam("token", accessToken)
            .post("oidc/introspect")
            .as(mapTypeRef);
        //Replaced pseudo eduID
        assertEquals(pseudonymiseResults.get("eduid"), results.get("eduid"));
    }

    @Test
    public void introspectionEduIdErrorPseudonymisation() throws IOException {
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

        stubFor(get(urlPathMatching("/attribute-manipulation"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withStatus(HttpStatus.SC_BAD_REQUEST)));

        Map<String, Object> results = given()
            .when()
            .header("Content-type", "application/x-www-form-urlencoded")
            .auth()
            .preemptive()
            .basic("resource-server-playground-client", "secret")
            .formParam("token", accessToken)
            .post("oidc/introspect")
            .as(mapTypeRef);
        //See src/main/resources/data/eduid.json
        assertEquals("3415570f-be91-4ba8-b9ba-e479d18094d5", results.get("eduid"));
    }

    @Test
    public void introspectionEduIdRSNotLinkedPseudonymisation() throws IOException {
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

        Map<Object, Object> pseudonymiseResults = Map.of(
            "eduid", UUID.randomUUID().toString(),
            "eduperson_principal_name", "some-eppn"
        );
        stubFor(get(urlPathMatching("/attribute-manipulation")).willReturn(aResponse()
            .withHeader("Content-Type", "application/json")
            .withBody(objectMapper.writeValueAsString(pseudonymiseResults))));

        Map<String, Object> results = given()
            .when()
            .header("Content-type", "application/x-www-form-urlencoded")
            .auth()
            .preemptive()
            .basic("resource-server-playground-client", "secret")
            .formParam("token", accessToken)
            .post("oidc/introspect")
            .as(mapTypeRef);
        //See the pseudonymiseResults with an eduperson_principal_name
        assertEquals(pseudonymiseResults.get("eduid"), results.get("eduid"));
        assertEquals(pseudonymiseResults.get("eduperson_principal_name"), results.get("eduperson_principal_name"));
    }


}
