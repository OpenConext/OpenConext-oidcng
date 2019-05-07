package oidc.user;

import lombok.Getter;
import oidc.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml.saml2.authentication.Assertion;

import java.util.Collection;
import java.util.Collections;

@Getter
public class OidcSamlAuthentication implements Authentication {

    private String name;
    private User user;

    public OidcSamlAuthentication(Assertion assertion, User user) {
        this.user = user;
        this.name = assertion.getSubject().getPrincipal().getValue();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
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
