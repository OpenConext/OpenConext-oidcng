package oidc.secure;

import oidc.AbstractIntegrationTest;
import oidc.model.AccessToken;
import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import org.junit.Test;
import org.springframework.data.mongodb.core.query.Query;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import static io.restassured.RestAssured.given;
import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertEquals;

public class AdminControllerTest extends AbstractIntegrationTest {

    @Test
    public void rolloverSigningKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
        resetAndCreateSigningKeys(1);
        assertEquals(Arrays.asList("key_1"),
                mongoTemplate.findAll(SigningKey.class).stream().map(SigningKey::getKeyId).sorted().collect(toList()));

        mongoTemplate.findAllAndRemove(new Query(), AccessToken.class);

        doRollover(201, "manage", "secret", "force-signing-key-rollover");

        assertEquals(Arrays.asList("key_2"),
                mongoTemplate.findAll(SigningKey.class).stream().map(SigningKey::getKeyId).sorted().collect(toList()));

    }

    @Test
    public void rollover401() {
        doRollover(401, "manage", "nope", "force-signing-key-rollover");
    }

    @Test
    public void rolloverSymmetricKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
        resetAndCreateSymmetricKeys(1);

        doRollover(201, "manage", "secret", "force-symmetric-key-rollover");

        assertEquals(1, mongoTemplate.count(new Query(), SymmetricKey.class));

    }

    private void doRollover(int expectedStatusCode, String user, String secret, String path) {
        given()
                .when()
                .header("Content-type", "application/json")
                .auth()
                .preemptive()
                .basic(user, secret)
                .get("manage/" + path)
                .then()
                .statusCode(expectedStatusCode);
    }
}