package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.model.RefreshToken;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;

public class RefreshTokenRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private RefreshTokenRepository subject;

    @Test
    public void findByInnerValue() {
        String value = RandomStringUtils.random(3200, true, true);
        String uuid = UUID.randomUUID().toString();
        subject.insert(new RefreshToken(uuid, uuid, "sub", "clientId", singletonList("openid"), "singing_key_id", new Date(), value, false, null));
        assertEquals(value, subject.findByInnerValue(uuid).getAccessTokenValue());
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void findByInnerValueEmpty() {
        subject.findByInnerValue("nope");
    }

    @Test
    public void deleteByExpiresInBefore() {
        subject.deleteAll();
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        subject.insert(new RefreshToken(UUID.randomUUID().toString(), "value", "sub", "clientId", singletonList("openid"),"singing_key_id", expiresIn, "value", false, null));

        long count = subject.deleteByExpiresInBefore(new Date());

        assertEquals(1L, count);
    }
}