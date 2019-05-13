package oidc.model;

import org.junit.Test;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AccessTokenTest {

    @Test
    public void isExpiredNotNull() {
        AccessToken accessToken = new AccessToken("value", "sub", "clientId", Collections.singletonList("openid"), null);

        assertFalse(accessToken.isExpired());
    }

    @Test
    public void isExpired() {
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        AccessToken accessToken = new AccessToken("value", "sub", "clientId", Collections.singletonList("openid"), expiresIn);

        assertTrue(accessToken.isExpired());
    }
}