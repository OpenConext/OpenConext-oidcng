package oidc.endpoints;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.oauth2.sdk.GrantType;
import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import org.junit.ClassRule;
import org.junit.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
        "cron.node-cron-job-responsible=false",
        "eduid.uri=http://localhost:8099/attribute-manipulation",
        "features.enforce-eduid-resource-server-linked-account=true"

    })
public class IntrospectEndpointEnabledEduIDEnforcementTest extends AbstractIntegrationTest {

    @ClassRule
    public static WireMockRule wireMockRule = new WireMockRule(8099);

    @Test
    public void introspectionEduIdInvalidPseudonymisation() throws IOException {
        Map<String, String> eduIdAttributePseudonymisationResult = new HashMap<>();
        eduIdAttributePseudonymisationResult.put("eduid", "pseudoEduid");

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

        Map<String, Object> result = given()
            .when()
            .header("Content-type", "application/x-www-form-urlencoded")
            .auth()
            .preemptive()
            .basic("resource-server-playground-client", "secret")
            .formParam("token", accessToken)
            .post("oidc/introspect")
            .as(mapTypeRef);

        assertEquals(false, result.get("active"));

    }

}
