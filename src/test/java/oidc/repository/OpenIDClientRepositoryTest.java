package oidc.repository;

import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;

public class OpenIDClientRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private OpenIDClientRepository subject;

    @Test(expected = EmptyResultDataAccessException.class)
    public void findByClientId() {
        subject.findByClientId("nope");
    }
}