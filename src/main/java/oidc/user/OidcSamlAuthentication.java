package oidc.user;

import lombok.Getter;
import lombok.NoArgsConstructor;
import oidc.model.User;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

@Getter
public class OidcSamlAuthentication extends AbstractAuthenticationToken {

    private String name;
    private User user;
    private String authenticationRequestID;

    public OidcSamlAuthentication() {
        super(new ArrayList<>());
    }

    public OidcSamlAuthentication(Assertion assertion, User user, String authenticationRequestID) {
        super(Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
        this.user = user;
        this.name = assertion.getSubject().getNameID().getValue();
        this.authenticationRequestID = authenticationRequestID;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return super.getAuthorities();
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return user;
    }

    @Override
    public Object getPrincipal() {
        return this.name;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        //nope
    }
}
