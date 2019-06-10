package oidc.repository;

import oidc.AbstractIntegrationTest;
import oidc.model.User;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class UserRepositoryTest extends AbstractIntegrationTest {

    @Autowired
    private UserRepository subject;

    @Test
    public void findOptionalBySub() {
        Optional<User> optionalUser = subject.findOptionalUserBySub("nope");
        assertFalse(optionalUser.isPresent());
    }

    @Test
    public void deleteBySubNotIn() {
        subject.deleteAll();
        IntStream.range(0, 5).forEach(i ->
                subject.insert(new User("sub" + i, "unspecifiedNameId", "authenticatingAuthority", "clientId",
                        Collections.emptyMap(), Collections.emptyList())));

        List<String> subs = Arrays.asList("sub0", "sub2", "sub2");
        Long res = subject.deleteBySubNotIn(subs);
        assertEquals(3L, res.longValue());

        List<String> remainingSubs = subject.findAll().stream().map(User::getSub).sorted().collect(Collectors.toList());
        assertEquals(subs.subList(0, 2), remainingSubs);

        res = subject.deleteBySubNotIn(new ArrayList<>());
        assertEquals(2L, res.longValue());

        remainingSubs = subject.findAll().stream().map(User::getSub).sorted().collect(Collectors.toList());
        assertEquals(0, remainingSubs.size());
    }


}