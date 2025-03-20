package oidc.secure;

import oidc.AbstractIntegrationTest;
import oidc.SeedUtils;
import oidc.endpoints.OidcEndpoint;
import oidc.model.*;
import oidc.repository.AccessTokenRepository;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static org.junit.Assert.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.data.mongodb.uri=mongodb://127.0.0.1:27017/oidc_test",
                "mongodb_db=oidc_test",
                "cron.node-cron-job-responsible=true"
        })
@SuppressWarnings("unchecked")
public class ResourceCleanerTest extends AbstractIntegrationTest implements SeedUtils, OidcEndpoint {

    @Autowired
    private ResourceCleaner subject;

    @Autowired
    private AccessTokenRepository accessTokenRepository;

    @Test
    public void clean() throws URISyntaxException {
        Class[] classes = {User.class, UserConsent.class, AccessToken.class, RefreshToken.class, AuthorizationCode.class, AuthenticationRequest.class};
        Stream.of(classes).forEach(clazz -> mongoTemplate.remove(new Query(), clazz));
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        Stream.of(
                accessToken("value", expiresIn),
                refreshToken(expiresIn),
                new AuthorizationCode("code", "sub", "clientId", emptyList(), new URI("http://redirectURI"),
                        "codeChallenge", "codeChallengeMethod", "nonce", emptyList(), true, expiresIn),
                new User("nope", "unspecifiedNameId", "authenticatingAuthority", "clientId",
                        Collections.emptyMap(), Collections.emptyList()),
                new AuthenticationRequest(UUID.randomUUID().toString(), expiresIn, "clientID", "http://localhost/authorize"),
                userConsent()
        ).forEach(o -> mongoTemplate.insert(o));

        subject.clean();

        Stream.of(classes).forEach(clazz -> assertEquals(0, mongoTemplate.findAll(clazz).size()));
    }

    @Test
    public void cleanEagerNegative() {
        String jwtId = UUID.randomUUID().toString();
        coCleanEager(jwtId, -5, false);
    }

    @Test
    public void cleanEagerPositive() {
        String jwtId = UUID.randomUUID().toString();
        coCleanEager(jwtId, 15, true);
    }

    private void coCleanEager(String jwtId, int validity, boolean present) {
        AccessToken accessToken = accessToken(jwtId, tokenValidity(validity));
        accessTokenRepository.insert(accessToken);
        subject.clean();
        Optional<AccessToken> optionalAccessToken = accessTokenRepository.findByJwtId(jwtId);
        assertEquals(present, optionalAccessToken.isPresent());
    }

    private UserConsent userConsent() {
        UserConsent userConsent = new UserConsent(new User("sub", "unspecifiedNameId", "http://mockidp",
                "clientId", Collections.emptyMap(), Collections.emptyList()), Arrays.asList("openid", "profile"), new OpenIDClient());
        Date lastAccessed = Date.from(new Date().toInstant().minus(365 * 10, ChronoUnit.DAYS).atZone(ZoneId.systemDefault()).toInstant());
        ReflectionTestUtils.setField(userConsent, "lastAccessed", lastAccessed);
        return userConsent;
    }
}