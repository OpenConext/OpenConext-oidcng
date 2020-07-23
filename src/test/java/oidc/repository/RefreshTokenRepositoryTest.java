package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.SeedUtils;
import oidc.model.AccessToken;
import oidc.model.RefreshToken;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.Charset;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class RefreshTokenRepositoryTest extends AbstractIntegrationTest implements SeedUtils {

    @Autowired
    private RefreshTokenRepository subject;

    @Test
    public void findByValue() {
        String value = RandomStringUtils.random(3200, true, true);
        subject.insert(refreshTokenWithValue(value));

        RefreshToken token = subject.findOptionalRefreshTokenByValue(value).get();
        assertEquals(AccessToken.computeInnerValueFromJWT(value),
                ReflectionTestUtils.getField(token, "value"));
    }

    public void findByValueEmpty() {
        assertFalse(subject.findOptionalRefreshTokenByValue("nope").isPresent());
    }

    @Test
    public void deleteByExpiresInBefore() {
        subject.deleteAll();
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        subject.insert(refreshToken(expiresIn));

        long count = subject.deleteByExpiresInBefore(new Date());

        assertEquals(1L, count);
    }
}