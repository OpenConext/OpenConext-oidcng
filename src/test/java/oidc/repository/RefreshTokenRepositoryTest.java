package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.SeedUtils;
import oidc.model.AccessToken;
import oidc.model.RefreshToken;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.util.ReflectionTestUtils;

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
    public void findByJwtId() {
        String jwtId = UUID.randomUUID().toString();
        RefreshToken refreshToken = refreshTokenWithValue(jwtId);
        subject.insert(refreshToken);

        RefreshToken token = subject.findByJwtId(jwtId).get();
        assertEquals(jwtId, token.getJwtId());
    }

    public void findByJwtEmpty() {
        assertFalse(subject.findByJwtId("nope").isPresent());
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