package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.model.AuthorizationCode;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.util.Collections.emptyList;
import static org.junit.Assert.assertEquals;

public class AuthorizationCodeRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private AuthorizationCodeRepository subject;

    @Test
    public void findByCode() throws URISyntaxException {
        String code = UUID.randomUUID().toString();
        subject.insert(new AuthorizationCode(code, "sub", "clientId", emptyList(), new URI("http://redirectURI"),
                "codeChallenge", "codeChallengeMethod", "nonce", emptyList(), true, new Date()));
        assertEquals(code, subject.findByCode(code).getCode());
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void findByInnerValueEmpty() {
        subject.findByCode("nope");
    }

    @Test
    public void deleteByExpiresInBefore() throws URISyntaxException {
        Date expiresIn = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        subject.insert(new AuthorizationCode("code", "sub", "clientId", emptyList(), new URI("http://redirectURI"),
                "codeChallenge", "codeChallengeMethod", "nonce", emptyList(), true, expiresIn));
        long count = subject.deleteByExpiresInBefore(new Date());

        assertEquals(1L, count);
    }

    @Test
    public void findSub() {
        IntStream.range(0, 3).forEach(i ->
        {
            try {
                subject.insert(new AuthorizationCode(UUID.randomUUID().toString(), "sub" + i, "clientId", emptyList(),
                        new URI("http://redirectURI"),
                        "codeChallenge", "codeChallengeMethod", "nonce", emptyList(), true, new Date()));
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        });
        List<String> subs = subject.findSub().stream().map(AuthorizationCode::getSub).collect(Collectors.toList());

        assertEquals(3, subs.size());
    }
}