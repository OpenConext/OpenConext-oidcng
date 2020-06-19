package oidc.model;

import oidc.TestUtils;
import org.junit.Test;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class UserTest implements TestUtils {

    @Test
    public void hashCodeEquals() throws IOException {
        User user1 = readUser("data/user.json");
        User user2 = readUser("data/user.json");
        assertEquals(user1, user2);
        assertEquals(user1.hashCode(), user2.hashCode());

        user1.setId("id");
        assertEquals(user1, user2);
        assertEquals(user1.hashCode(), user2.hashCode());

        user1.getAttributes().put("preferred_username", "changed");
        assertNotEquals(user1, user2);
        assertNotEquals(user1.hashCode(), user2.hashCode());
    }

    @Test
    public void equals() throws Exception {
        User pre = readUser("oidc/user_pre.json");
        User post = readUser("oidc/user_post.json");

        assertTrue(pre.equals(post));
    }

    private User readUser(String path) throws IOException {
        return objectMapper.readValue(readFile(path).getBytes(), User.class);
    }

}