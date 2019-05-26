package oidc.model;

import oidc.SeedUtils;
import org.junit.Test;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static java.util.Collections.singletonList;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AccessTokenTest implements SeedUtils {

    @Test
    public void isExpiredNotNull() {
        AccessToken accessToken = accessToken("value", (Date)null);

        assertFalse(accessToken.isExpired(Clock.systemDefaultZone()));
    }

    @Test
    public void isExpired() {
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        AccessToken accessToken = accessToken("value", expiresIn);

        assertTrue(accessToken.isExpired(Clock.systemDefaultZone()));
    }
}