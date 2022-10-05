package oidc.api;

import com.fasterxml.jackson.core.JsonProcessingException;
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
import java.util.*;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;

public class TokenControllerTest extends AbstractIntegrationTest {

    private final String unspecifiedId = "urn:collab:person:eduid.nl:7d4fca9b-2169-4d55-8347-73cf29b955a2";
    private final String unspecifiedIdHash = KeyGenerator.oneWayHash(unspecifiedId, "secret");

    @Before
    public void before() throws IOException {
        super.before();
        seed();
    }

    @Test
    public void getTokens() {
        List<Map<String, Object>> tokens = doGetTokens(APIVersion.V1);
        assertEquals(4, tokens.size());
    }

    @Test
    public void getTokensV2() {
        List<Map<String, Object>> tokens = doGetTokens(APIVersion.V2);
        assertEquals(2, tokens.size());
        List<Map<String, Object>> resourceServers = (List<Map<String, Object>>) tokens.get(0).get("audiences");
        List<Map<String, Object>> scopes = (List<Map<String, Object>>) resourceServers.get(0).get("scopes");
        assertEquals("groups", scopes.get(0).get("name"));
    }

    @Test
    public void deleteTokens() throws JsonProcessingException {
        doDeleteTokens(APIVersion.V1);
    }

    @Test
    public void deleteTokensV2() throws JsonProcessingException {
        doDeleteTokens(APIVersion.V2);
    }

    private void doDeleteTokens(APIVersion apiVersion) throws JsonProcessingException {
        List<Map<String, Object>> tokens = doGetTokens(APIVersion.V1);

        List<TokenRepresentation> body = tokens.stream()
                .map(token -> new TokenRepresentation((String) token.get("id"), TokenType.valueOf((String) token.get("type"))))
                .collect(Collectors.toList());
        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(body));
        given()
                .when()
                .header("Content-type", "application/json")
                .auth()
                .preemptive()
                .basic("eduid", "secret")
                .body(body)
                .put(apiVersion.equals(APIVersion.V1) ? "tokens" : "v2/tokens")
                .then()
                .statusCode(HttpStatus.NO_CONTENT.value());
        tokens = doGetTokens(APIVersion.V1);
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
        return new RefreshToken(UUID.randomUUID().toString(), accessToken(clientId), Date.from(Instant.now().minus(90, ChronoUnit.DAYS)));
    }

    private List<Map<String, Object>> doGetTokens(APIVersion apiVersion) {
        return given()
                .when()
                .header("Content-type", "application/json")
                .auth()
                .preemptive()
                .basic("eduid", "secret")
                .queryParam("unspecifiedID", "urn:collab:person:eduid.nl:7d4fca9b-2169-4d55-8347-73cf29b955a2")
                .get(apiVersion.equals(APIVersion.V1) ? "tokens" : "/v2/tokens")
                .as(new TypeRef<>() {
                });
    }
}