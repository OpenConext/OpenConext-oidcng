package oidc.secure;

import oidc.AbstractIntegrationTest;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.RefreshToken;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.query.Query;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;

public class ResourceCleanerTest extends AbstractIntegrationTest {

    @Autowired
    private ResourceCleaner subject;

    @Test
    public void clean() {
        Stream.of(AccessToken.class, RefreshToken.class, AuthorizationCode.class)
                .forEach(clazz -> mongoTemplate.remove(new Query(), clazz));
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        Stream.of(
                new AccessToken("value", "sub", "clientId", singletonList("openid"), expiresIn, false),
                new RefreshToken("value", "sub", "clientId", singletonList("openid"), expiresIn, "value", false),
                new AuthorizationCode("code", "sub", "clientId", emptyList(), "redirectUri",
                        "codeChallenge", "codeChallengeMethod", emptyList(), expiresIn)
        ).forEach(o -> mongoTemplate.insert(o));

        subject.clean();

        Stream.of(AccessToken.class, RefreshToken.class, AuthorizationCode.class)
                .forEach(clazz -> assertEquals(0, mongoTemplate.findAll(clazz).size()));
    }
}