package oidc;


import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.restassured.RestAssured.given;


/**
 * Override the @WebIntegrationTest annotation if you don't want to have mock SAML authentication
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.data.mongodb.uri=mongodb://localhost:27017/oidc_test","mongodb_db=oidc_test"})
@ActiveProfiles("dev")
public abstract class AbstractIntegrationTest implements TestUtils {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractIntegrationTest.class);

    @LocalServerPort
    protected int port;

    @Before
    public void before() throws Exception {
        RestAssured.port = port;
    }

    protected String doAuthorize(String clientId) {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid profile");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", clientId);
        queryParams.put("redirect_uri", "http://localhost:8080");
        queryParams.put("state", "example");

        Response response = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize");

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
