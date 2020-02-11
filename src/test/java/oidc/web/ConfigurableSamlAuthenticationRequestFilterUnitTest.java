package oidc.web;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ConfigurableSamlAuthenticationRequestFilterUnitTest {

    private ConfigurableSamlAuthenticationRequestFilter subject =
            new ConfigurableSamlAuthenticationRequestFilter(null, null, null, null);

    @Test
    public void scopedSSOLocation() {
        String s = subject.scopedSSOLocation("idp_hash",
                "authentication/idp/single-sign-on/first_hash");
        assertEquals("authentication/idp/single-sign-on/idp_hash", s);

        s = subject.scopedSSOLocation(" ",
                "authentication/idp/single-sign-on/first_hash");
        assertEquals("authentication/idp/single-sign-on", s);

        s = subject.scopedSSOLocation(null,
                "authentication/idp/single-sign-on");
        assertEquals("authentication/idp/single-sign-on", s);
    }
}