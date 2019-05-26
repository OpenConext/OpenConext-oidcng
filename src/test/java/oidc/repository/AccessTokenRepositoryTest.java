package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.SeedUtils;
import oidc.model.AccessToken;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.stream.IntStream;

import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;

public class AccessTokenRepositoryTest extends AbstractIntegrationTest implements SeedUtils {

    @Autowired
    private AccessTokenRepository accessTokenRepository;

    @Test(expected = EmptyResultDataAccessException.class)
    public void findByValue() {
        accessTokenRepository.findByValue("nope");
    }

    @Test
    public void findByValueOptional() {
        assertEquals(false, accessTokenRepository.findOptionalAccessTokenByValue("nope").isPresent());
    }

    @Test
    public void findByInnerValue() {
        String value = RandomStringUtils.random(3200, true, true);
        accessTokenRepository.insert(accessToken(value, new Date()));

        AccessToken accessToken = accessTokenRepository.findByValue(value);
        assertEquals(value, ReflectionTestUtils.getField(accessToken, "innerValue"));

        assertEquals(true, accessTokenRepository.findOptionalAccessTokenByValue(value).isPresent());
    }

    @Test
    public void deleteByExpiresInBefore() {
        accessTokenRepository.deleteAll();
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        accessTokenRepository.insert(accessToken("value", expiresIn));

        long count = accessTokenRepository.deleteByExpiresInBefore(new Date());

        assertEquals(1L, count);
    }

}