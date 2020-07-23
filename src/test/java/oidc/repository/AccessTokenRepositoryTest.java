package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.SeedUtils;
import oidc.crypto.KeyGenerator;
import oidc.model.AccessToken;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.Charset;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class AccessTokenRepositoryTest extends AbstractIntegrationTest implements SeedUtils {

    @Autowired
    private AccessTokenRepository accessTokenRepository;

    @Test
    public void findByValueOptional() {
        assertEquals(false, accessTokenRepository.findOptionalAccessTokenByValue("nope").isPresent());
    }

    @Test
    public void findByValue() {
        String value = RandomStringUtils.random(3200, true, true);
        accessTokenRepository.insert(accessToken(value, new Date()));

        AccessToken accessToken = accessTokenRepository.findOptionalAccessTokenByValue(value).get();
        assertEquals(AccessToken.computeInnerValueFromJWT(value),
                ReflectionTestUtils.getField(accessToken, "value"));
    }

    @Test
    public void deleteByExpiresInBefore() {
        accessTokenRepository.deleteAll();
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        accessTokenRepository.insert(accessToken("value", expiresIn));

        long count = accessTokenRepository.deleteByExpiresInBefore(new Date());

        assertEquals(1L, count);
    }

    @Test
    public void findAccessTokenByUnspecifiedUrnHash() {
        String unspecifiedUrnHash = KeyGenerator.oneWayHash("urn:collab:person:eduid.nl:7d4fca9b-2169-4d55-8347-73cf29b955a2", UUID.randomUUID().toString());
        accessTokenRepository.insert(accessToken(unspecifiedUrnHash));

        List<AccessToken> tokens = accessTokenRepository.findAccessTokenByUnspecifiedUrnHash(unspecifiedUrnHash);
        assertEquals(1, tokens.size());
    }

}