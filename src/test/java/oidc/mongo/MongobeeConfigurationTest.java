package oidc.mongo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import oidc.AbstractIntegrationTest;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.RefreshToken;
import org.junit.Test;
import org.springframework.data.mongodb.core.query.Criteria;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class MongobeeConfigurationTest extends AbstractIntegrationTest {

    private MongobeeConfiguration subject = new MongobeeConfiguration();

    @Test
    public void migrateToken() throws JsonProcessingException {
        mongoTemplate.dropCollection(AccessToken.class);
        mongoTemplate.dropCollection(RefreshToken.class);
        mongoTemplate.save(objectMapper.readValue(readFile("tokens/accesstoken.json"), Map.class), "access_tokens");
        mongoTemplate.save(objectMapper.readValue(readFile("tokens/refreshtoken.json"), Map.class), "refresh_tokens");

        subject.migrateTokens(mongoTemplate);

        List<AccessToken> accessTokens = mongoTemplate.findAll(AccessToken.class);
        assertEquals(1, accessTokens.size());
        accessTokens.forEach(accessToken -> {
            String innerValue = accessToken.getInnerValue();
            assertJwtId(accessToken, innerValue);
        });
        List<RefreshToken> refreshTokens = mongoTemplate.findAll(RefreshToken.class);
        assertEquals(1, refreshTokens.size());
        refreshTokens.forEach(refreshToken -> {
            String accessTokenValue = refreshToken.getAccessTokenValue();
            assertJwtId(refreshToken, accessTokenValue);
        });
    }

    @SneakyThrows
    private void assertJwtId(AccessToken accessToken, String innerValue) {
        SignedJWT signedJWT = SignedJWT.parse(innerValue);
        String jwtId = signedJWT.getJWTClaimsSet().getJWTID();
        assertEquals(jwtId, accessToken.getJwtId());
    }
}