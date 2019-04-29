package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.model.User;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Optional;

import static org.junit.Assert.assertFalse;

public class UserRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private UserRepository subject;

    @Test
    public void findOptionalBySub() {
        Optional<User> optionalUser = subject.findOptionalUserBySub("nope");
        assertFalse(optionalUser.isPresent());
    }


}