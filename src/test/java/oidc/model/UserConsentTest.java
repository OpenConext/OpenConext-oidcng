package oidc.model;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static org.junit.Assert.*;

public class UserConsentTest {

    @Test
    public void renewConsentRequired() {
        UserConsent userConsent = userConsent();
        User user = user();
        int i = user.hashCode();
        boolean b = userConsent.renewConsentRequired(user, emptyList());
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        User user2 = user();
        int j = user2.hashCode();
        System.out.println(b);
    }


    private UserConsent userConsent() {
        User user = user();
        List<String> scopes = Arrays.asList("openid");
        OpenIDClient openIDClient = new OpenIDClient("clientId", emptyList(), emptyList(), emptyList());
        return new UserConsent(user, scopes, openIDClient);
    }

    private User user() {
        return new User("sub", "unspecifiedNameId",
                "authenticatingAuthority", "clientId",
                attributes(), Collections.singletonList("acr"));
    }

    private Map<String, Object> attributes() {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("urn:mace_something", Collections.singletonList("value"));
        return attributes;
    }
}