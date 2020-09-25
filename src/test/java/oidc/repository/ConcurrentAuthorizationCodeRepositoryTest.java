package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.endpoints.ConcurrentAuthorizationCodeRepository;
import oidc.model.AuthorizationCode;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Date;

import static org.junit.Assert.*;

public class ConcurrentAuthorizationCodeRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private AuthorizationCodeRepository authorizationCodeRepository;

    @Autowired
    private ConcurrentAuthorizationCodeRepository concurrentAuthorizationCodeRepository;

    @Test
    public void findByCodeAndMarkUsed() throws URISyntaxException {
        authorizationCodeRepository.save(new AuthorizationCode("code", "sub","client_id",
                Collections.singletonList("openid"), new URI("http://localhost"), null,
                null,"nonce",null, true, new Date()));
        assertNull(concurrentAuthorizationCodeRepository.findByCodeNotAlreadyUsedAndMarkAsUsed("nope"));

        AuthorizationCode authorizationCode = concurrentAuthorizationCodeRepository.findByCodeNotAlreadyUsedAndMarkAsUsed("code");
        assertTrue(authorizationCode.isAlreadyUsed());

        assertTrue(authorizationCodeRepository.findByCode("code").isAlreadyUsed());
        assertNull(concurrentAuthorizationCodeRepository.findByCodeNotAlreadyUsedAndMarkAsUsed("code"));
    }
}