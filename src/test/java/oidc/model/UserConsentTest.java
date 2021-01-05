package oidc.model;

import oidc.SeedUtils;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.joining;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UserConsentTest implements SeedUtils {

    @Test
    public void renewConsentRequired() {
        UserConsent userConsent = userConsent("groups");
        boolean renewConsentRequired = userConsent.renewConsentRequired(Arrays.asList("groups"));
        assertFalse(renewConsentRequired);

        renewConsentRequired = userConsent.renewConsentRequired(Arrays.asList("new_groups"));
        assertTrue(renewConsentRequired);
    }


    private UserConsent userConsent(String... scopes) {
        List<String> scopeList = Arrays.asList(scopes);
        OpenIDClient openIDClient = new OpenIDClient("clientId", emptyList(), emptyList(), emptyList());
        return new UserConsent(user("urn:mace:something"), scopeList, openIDClient);
    }

}