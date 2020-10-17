package oidc.saml;

import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "cron.node-cron-job-responsible=false"
        })
@ActiveProfiles(value = "", inheritProfiles = false)
public class AuthnRequestConverterTest extends AbstractIntegrationTest {

    static {
        OpenSamlInitializationService.initialize();
    }

    @Test
    public void testSaml() throws IOException {
        Map<String, String> queryParams = new HashMap<>();
        String clientId = "mock-sp";
        queryParams.put("scope", "openid");
        queryParams.put("client_id", clientId);
        queryParams.put("response_type", "code");
        queryParams.put("redirect_uri", openIDClient(clientId).getRedirectUrls().get(0));
        Response response = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize");
        Map<String, String> cookies = response.getCookies();

        String location = response.getHeader("Location");
        assertTrue(location.endsWith("/saml2/authenticate/oidcng"));

        response = given().redirects().follow(false)
                .cookies(cookies)
                .when()
                .get("saml2/authenticate/oidcng");

        String ebLocation = response.getHeader("Location");
        assertTrue(ebLocation.startsWith("https://engine"));

        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(ebLocation).build().getQueryParams();
        Arrays.asList("SAMLRequest", "SigAlg", "Signature").forEach(param -> assertTrue(params.containsKey(param)));
    }

}