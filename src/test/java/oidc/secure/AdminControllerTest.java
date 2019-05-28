package oidc.secure;

import oidc.AbstractIntegrationTest;
import oidc.model.AccessToken;
import oidc.model.SigningKey;
import org.junit.Test;
import org.springframework.data.mongodb.core.BulkOperations;
import org.springframework.data.mongodb.core.query.BasicQuery;
import org.springframework.data.mongodb.core.query.Query;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;

import static io.restassured.RestAssured.given;
import static java.util.stream.Collectors.toList;
import static org.junit.Assert.*;

public class AdminControllerTest extends AbstractIntegrationTest {

    @Test
    public void rollover() throws NoSuchProviderException, NoSuchAlgorithmException {
        resetAndCreateSigningKeys(1);
        assertEquals(Arrays.asList("key_1"),
                mongoTemplate.findAll(SigningKey.class).stream().map(SigningKey::getKeyId).sorted().collect(toList()));

        mongoTemplate.findAllAndRemove(new Query(), AccessToken.class);

        doRollover(201, "manage", "secret");

        assertEquals(Arrays.asList("key_2"),
                mongoTemplate.findAll(SigningKey.class).stream().map(SigningKey::getKeyId).sorted().collect(toList()));

    }

    @Test
    public void rollover401() {
        doRollover(401, "manage", "nope");
    }

    private void doRollover(int expectedStatusCode, String user, String secret) {
        given()
                .when()
                .header("Content-type", "application/json")
                .auth()
                .preemptive()
                .basic(user, secret)
                .get("manage/force-signing-key-rollover" )
                .then()
                .statusCode(expectedStatusCode);
    }
}