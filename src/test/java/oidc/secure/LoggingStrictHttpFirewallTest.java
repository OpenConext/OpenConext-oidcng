package oidc.secure;

import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.firewall.RequestRejectedException;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.*;

public class LoggingStrictHttpFirewallTest {

    private LoggingStrictHttpFirewall firewall = new LoggingStrictHttpFirewall();

    @Test(expected = RequestRejectedException.class)
    public void request() {
        firewall.getFirewalledRequest(new MockHttpServletRequest(HttpMethod.GET.name(), "oidc//.//introspect"));


    }

}