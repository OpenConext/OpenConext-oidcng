package oidc.api;

import io.restassured.common.mapper.TypeRef;
import oidc.AbstractIntegrationTest;
import oidc.crypto.KeyGenerator;
import oidc.model.AccessToken;
import oidc.model.RefreshToken;
import oidc.model.TokenRepresentation;
import oidc.model.TokenType;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

public class TokenControllerTest extends AbstractIntegrationTest {

    private String user = "eduid";
    private String password = "secret";
    private String unspecifiedId = "urn:collab:person:eduid.nl:7d4fca9b-2169-4d55-8347-73cf29b955a2";
    private String unspecifiedIdHash = KeyGenerator.oneWayHash(unspecifiedId, "secret");

    @Before
    public void before() throws IOException {
        super.before();
        seed();
    }

    @Test
    public void getTokens() {
        List<Map<String, Object>> tokens = doGetTokens(user, password, unspecifiedId);
        assertEquals(4, tokens.size());
    }

    @Test
    public void deleteTokens() {
        List<Map<String, Object>> tokens = doGetTokens(user, password, unspecifiedId);

        List<TokenRepresentation> body = tokens.stream()
                .map(token -> new TokenRepresentation((String) token.get("id"), TokenType.valueOf((String) token.get("type"))))
                .collect(Collectors.toList());
        given()
                .when()
                .header("Content-type", "application/json")
                .auth()
                .preemptive()
                .basic(user, password)
                .body(body)
                .put("tokens")
                .then()
                .statusCode(HttpStatus.NO_CONTENT.value());
        tokens = doGetTokens(user, password, unspecifiedId);
        assertEquals(0, tokens.size());
    }

    private void seed() {
        Arrays.asList(accessToken("mock-rp"), accessToken("playground_client"), accessToken("deleted"))
                .forEach(token -> mongoTemplate.save(token, "access_tokens"));
        Arrays.asList(refreshToken("mock-rp"), refreshToken("playground_client"), refreshToken("deleted"))
                .forEach(token -> mongoTemplate.save(token, "refresh_tokens"));

    }

    private AccessToken accessToken(String clientId) {
        return new AccessToken(UUID.randomUUID().toString(), "sub", clientId, Arrays.asList("openid", "groups", "nope"),
                null, Date.from(Instant.now().minus(90, ChronoUnit.DAYS)), false,
                null, unspecifiedIdHash);
    }

    private RefreshToken refreshToken(String clientId) {
        return new RefreshToken(UUID.randomUUID().toString(), "sub", clientId, Arrays.asList("openid", "groups", "nope"),
                Date.from(Instant.now().minus(90, ChronoUnit.DAYS)), "accessTokenValue",
                false, unspecifiedIdHash);
    }

    private List<Map<String, Object>> doGetTokens(String user, String secret, String unspecifiedId) {
        return given()
                .when()
                .header("Content-type", "application/json")
                .auth()
                .preemptive()
                .basic(user, secret)
                .queryParam("unspecifiedID", unspecifiedId)
                .get("tokens")
                .as(new TypeRef<List<Map<String, Object>>>() {
                });
    }
}