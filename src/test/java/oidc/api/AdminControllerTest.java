package oidc.api;

import oidc.AbstractIntegrationTest;
import oidc.model.AccessToken;
import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.query.Query;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

import static io.restassured.RestAssured.given;
import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class AdminControllerTest extends AbstractIntegrationTest {

    private @Value("${manage.user}") String user;
    private @Value("${manage.password}") String password;

    @Test
    public void rolloverSigningKeys() throws GeneralSecurityException, ParseException, IOException {
        resetAndCreateSigningKeys(1);
        List<String> keys = mongoTemplate.findAll(SigningKey.class).stream().map(SigningKey::getKeyId).sorted().collect(toList());
        assertEquals(1, keys.size());

        mongoTemplate.findAllAndRemove(new Query(), AccessToken.class);

        doRollover(201, user, password, "force-signing-key-rollover");

        List<String> newKeys = mongoTemplate.findAll(SigningKey.class).stream().map(SigningKey::getKeyId).sorted().collect(toList());
        assertEquals(1, newKeys.size());

        assertNotEquals(keys.get(0), newKeys.get(0));
    }

    @Test
    public void rollover401() {
        doRollover(401, "manage", "nope", "force-signing-key-rollover");
    }

    @Test
    public void rolloverSymmetricKeys() throws GeneralSecurityException, IOException {
        resetAndCreateSymmetricKeys(1);

        doRollover(201, user, password, "force-symmetric-key-rollover");

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