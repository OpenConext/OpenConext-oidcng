package oidc.model;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.Assert.*;

public class UserConsentTest {

    @Test
    public void renewConsentRequired() {
        UserConsent userConsent = userConsent("urn:mace_something");
        User user = user("urn:mace_something");
        boolean renewConsentRequired = userConsent.renewConsentRequired(user, emptyList());
        assertFalse(renewConsentRequired);

        user = user("urn:mace_other");
        renewConsentRequired = userConsent.renewConsentRequired(user, emptyList());
        assertTrue(renewConsentRequired);

        user = user("urn:mace_something");
        renewConsentRequired = userConsent.renewConsentRequired(user, singletonList("profile"));
        assertTrue(renewConsentRequired);
    }


    private UserConsent userConsent(String key) {
        User user = user(key);
        List<String> scopes = Arrays.asList("openid");
        OpenIDClient openIDClient = new OpenIDClient("clientId", emptyList(), emptyList(), emptyList());
        return new UserConsent(user, scopes, openIDClient);
    }

    private User user(String key) {
        return new User("sub", "unspecifiedNameId",
                "authenticatingAuthority", "clientId",
                attributes(key), Collections.singletonList("acr"));
    }

    private Map<String, Object> attributes(String key) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(key, Collections.singletonList("value"));
        return attributes;
    }
}