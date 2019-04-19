package oidc;


import io.restassured.RestAssured;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;


/**
 * Override the @WebIntegrationTest annotation if you don't want to have mock SAML authentication
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.data.mongodb.uri=mongodb://localhost:27017/oidc_test"})
@ActiveProfiles("dev")
public abstract class AbstractIntegrationTest implements TestUtils {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractIntegrationTest.class);

    @LocalServerPort
    protected int port;

    @Before
    public void before() throws Exception {
        RestAssured.port = port;
    }

}
