package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.model.AuthorizationCode;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

import static java.util.Collections.emptyList;
import static org.junit.Assert.assertEquals;

public class AuthorizationCodeRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private AuthorizationCodeRepository subject;

    @Test
    public void findByCode() {
        String code = UUID.randomUUID().toString();
        subject.insert(new AuthorizationCode(code, "sub", "clientId", emptyList(), "redirectUri",
                "codeChallenge", "codeChallengeMethod", emptyList(), new Date()));
        assertEquals(code, subject.findByCode(code).getCode());
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void findByInnerValueEmpty() {
        subject.findByCode("nope");
    }

    @Test
    public void deleteByExpiresInBefore() {
        subject.deleteAll();
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        subject.insert(new AuthorizationCode("code", "sub", "clientId", emptyList(), "redirectUri",
                "codeChallenge", "codeChallengeMethod", emptyList(), new Date()));
        long count = subject.deleteByExpiresInBefore(new Date());

        assertEquals(1L, count);
    }
}