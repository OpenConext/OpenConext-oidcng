package oidc.user;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OidcSamlAuthenticationTest {

    private final OidcSamlAuthentication oidcSamlAuthentication = new OidcSamlAuthentication();

    @Test
    void getAuthorities() {
        assertEquals(0, oidcSamlAuthentication.getAuthorities().size());
    }

    @Test
    void getCredentials() {
        assertNull(oidcSamlAuthentication.getCredentials());
    }

    @Test
    void setAuthenticated() {
        oidcSamlAuthentication.setAuthenticated(false);
        assertTrue(oidcSamlAuthentication.isAuthenticated());
    }
}
