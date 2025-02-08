package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.model.OpenIDClient;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class OpenIDClientRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private OpenIDClientRepository subject;

    @Test
    public void findByClientIdIn() {
        assertEquals(3, subject.findByClientIdIn(
                Arrays.asList("rp-jwt-authentication", "resource-server-playground-client", "mock-sp")).size());
    }

    @Test
    public void findByClientIdInNope() {
        assertEquals(0, subject.findByClientIdIn(Collections.singletonList("nope")).size());
    }

    @Test
    public void findByScopesNameIn() {
        List<OpenIDClient> clients = subject.findByScopes_NameIn(new HashSet<>(Arrays.asList("https://voot.surfconext.nl/groups")));
        assertEquals(1, clients.size());
    }

    @Test
    public void findByScopesNameInMultiple() {
        List<OpenIDClient> clients = subject.findByScopes_NameIn(new HashSet<>(Arrays.asList("groups")));
        assertEquals(6, clients.size());
    }

}