package oidc.secure;

import oidc.AbstractIntegrationTest;
import oidc.SeedUtils;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.RefreshToken;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.mongodb.core.query.Query;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.data.mongodb.uri=mongodb://127.0.0.1:27017/oidc_test",
                "mongodb_db=oidc_test",
                "cron.node-cron-job-responsible=true"
        })
public class ResourceCleanerTest extends AbstractIntegrationTest implements SeedUtils {

    @Autowired
    private ResourceCleaner subject;

    @Test
    public void clean() {
        Stream.of(AccessToken.class, RefreshToken.class, AuthorizationCode.class)
                .forEach(clazz -> mongoTemplate.remove(new Query(), clazz));
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        Stream.of(
                accessToken("value", expiresIn),
                new RefreshToken("value", "sub", "clientId", singletonList("openid"), expiresIn, "value", false),
                new AuthorizationCode("code", "sub", "clientId", emptyList(), "redirectUri",
                        "codeChallenge", "codeChallengeMethod", "nonce", emptyList(), expiresIn)
        ).forEach(o -> mongoTemplate.insert(o));

        subject.clean();

        Stream.of(AccessToken.class, RefreshToken.class, AuthorizationCode.class)
                .forEach(clazz -> assertEquals(0, mongoTemplate.findAll(clazz).size()));
    }
}