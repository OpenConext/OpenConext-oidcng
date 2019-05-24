package oidc.secure;

import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.firewall.RequestRejectedException;

public class LoggingStrictHttpFirewallTest {

    private LoggingStrictHttpFirewall firewall = new LoggingStrictHttpFirewall();

    @Test(expected = RequestRejectedException.class)
    public void request() {
        firewall.getFirewalledRequest(new MockHttpServletRequest(HttpMethod.GET.name(), "oidc//.//introspect"));


    }

}