package oidc.model;

import oidc.TestUtils;
import org.junit.Test;

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.util.Date;

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