package oidc.model;

import org.junit.Test;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuthorizationCodeTest {

    @Test
    public void isExpiredNotNull() {
        AuthorizationCode authorizationCode = authorizationCode(null);
        assertFalse(authorizationCode.isExpired(Clock.systemDefaultZone()));
    }

    @Test
    public void isExpired() {
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        AuthorizationCode authorizationCode = authorizationCode(expiresIn);
        assertTrue(authorizationCode.isExpired(Clock.systemDefaultZone()));
    }

    private AuthorizationCode authorizationCode(Date expiresIn) {
        return new AuthorizationCode("code", "sub", "clientId",
                singletonList("openid"), "http://redirect_uri", "codeChallende",
                "codeChallengeMethod", "nonce", emptyList(), expiresIn);
    }
}