package oidc.repository;

import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;

public class OpenIDClientRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private OpenIDClientRepository subject;

    @Test(expected = EmptyResultDataAccessException.class)
    public void findByClientId() {
        subject.findByClientId("nope");
    }

    @Test
    public void findByClientIdIn() {
        assertEquals(3, subject.findByClientIdIn(
                Arrays.asList("rp-jwt-authentication", "resource-server-playground-client", "mock-sp")).size());
    }

    @Test
    public void findByClientIdInNope() {
        assertEquals(0, subject.findByClientIdIn(Collections.singletonList("nope")).size());
    }
}