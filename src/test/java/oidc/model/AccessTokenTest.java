package oidc.model;

import org.junit.Test;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static java.util.Collections.singletonList;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AccessTokenTest {

    @Test
    public void isExpiredNotNull() {
        AccessToken accessToken = new AccessToken("value", "sub", "clientId",
                singletonList("openid"), null, false);

        assertFalse(accessToken.isExpired(Clock.systemDefaultZone()));
    }

    @Test
    public void isExpired() {
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        AccessToken accessToken = new AccessToken("value", "sub", "clientId",
                singletonList("openid"), expiresIn, false);

        assertTrue(accessToken.isExpired(Clock.systemDefaultZone()));
    }
}