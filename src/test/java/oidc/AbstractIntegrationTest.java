package oidc;


import com.fasterxml.jackson.core.type.TypeReference;
import io.restassured.RestAssured;
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
 * Override the @WebIntegrationTest annotation if you don't want to have mock SAML authentication
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

    private List<OpenIDClient> openIDClients;

    @Before
    public void before() throws IOException {
        RestAssured.port = port;
        mongoTemplate.dropCollection(OpenIDClient.class);
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

    protected String doAuthorize(String clientId) {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid profile");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", clientId);
        queryParams.put("redirect_uri", "http%3A%2F%2Flocalhost%3A8080");
        queryParams.put("state", "example");

        Response response = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize");
        assertEquals(302, response.getStatusCode());

        String location = response.getHeader("Location");
        Matcher matcher = Pattern.compile(
                "\\Qhttp://localhost:8080?code=\\E(.*)\\Q&state=example\\E")
                .matcher(location);
        matcher.find();
        return matcher.group(1);
    }

    protected String doAuthorize() {
        return doAuthorize("http@//mock-sp");
    }


}
