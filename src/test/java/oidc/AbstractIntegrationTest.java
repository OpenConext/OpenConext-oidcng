package oidc;


import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.oauth2.sdk.GrantType;
import io.restassured.RestAssured;
import io.restassured.mapper.TypeRef;
import io.restassured.response.Response;
import oidc.model.OpenIDClient;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.mongodb.core.BulkOperations;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;


/**
 * Override the @ActiveProfiles annotation if you don't want to have mock SAML authentication
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.data.mongodb.uri=mongodb://localhost:27017/oidc_test", "mongodb_db=oidc_test"})
@ActiveProfiles("dev")
public abstract class AbstractIntegrationTest implements TestUtils {

    @LocalServerPort
    protected int port;

    @Autowired
    protected MongoTemplate mongoTemplate;

    protected TypeRef<Map<String, Object>> mapTypeRef = new TypeRef<Map<String, Object>>() {
    };

    private List<OpenIDClient> openIDClients;

    @Before
    public void before() throws IOException {
        RestAssured.port = port;
        mongoTemplate.bulkOps(BulkOperations.BulkMode.ORDERED, OpenIDClient.class)
                .remove(new Query())
                .insert(openIDClients())
                .execute();
    }

    protected List<OpenIDClient> openIDClients() throws IOException {
        if (CollectionUtils.isEmpty(this.openIDClients)) {
            this.openIDClients = serviceProviders().stream().map(OpenIDClient::new).collect(Collectors.toList());
        }
        return this.openIDClients;
    }

    protected List<Map<String, Object>> serviceProviders() throws IOException {
        return objectMapper.readValue(new ClassPathResource("manage/service_providers.json").getInputStream(),
                new TypeReference<List<Map<String, Object>>>() {
                });
    }

    protected String doAuthorize() {
        String location = doAuthorize("http@//mock-sp", "code", null, null);
        Matcher matcher = Pattern.compile(
                "\\Qhttp://localhost:8080?code=\\E(.*)\\Q&state=example\\E")
                .matcher(location);
        matcher.find();
        return matcher.group(1);
    }

    protected String doAuthorize(String clientId, String responseType, String responseMode, String nonce) {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid profile");
        queryParams.put("response_type", responseType);
        queryParams.put("client_id", clientId);
        queryParams.put("redirect_uri", "http%3A%2F%2Flocalhost%3A8080");
        queryParams.put("state", "example");
        if (StringUtils.hasText(responseMode)) {
            queryParams.put("response_mode", responseMode);
        }
        if (StringUtils.hasText(nonce)) {
            queryParams.put("nonce", nonce);
        }

        Response response = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize");
        assertEquals(302, response.getStatusCode());

        return response.getHeader("Location");
    }

    protected Map<String, Object> doToken(String code) {
        return doToken(code, "http@//mock-sp", "secret", GrantType.AUTHORIZATION_CODE);
    }

    protected Map<String, Object> doToken(String code, String clientId, String secret, GrantType grantType) {
        return given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .auth()
                .preemptive()
                .basic(clientId, secret)
                .formParam("grant_type", grantType.getValue())
                .formParam(grantType.equals(GrantType.CLIENT_CREDENTIALS) ? "bogus" : "code", code)
                .post("oidc/token")
                .as(Map.class);
    }


}
