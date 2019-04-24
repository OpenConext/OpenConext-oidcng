package oidc.user;

import lombok.Getter;
import lombok.Setter;
import oidc.model.User;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;

import java.io.Serializable;

@Getter
public class OidcSamlAuthentication extends DefaultSamlAuthentication implements Serializable {

    private String principalName;
    private User user;

    public OidcSamlAuthentication(boolean authenticated, Assertion assertion, String assertingEntityId, String holdingEntityId, String relayState, User user) {
        super(authenticated, null, assertingEntityId, holdingEntityId, relayState);
        this.user = user;
        this.principalName = assertion.getSubject().getPrincipal().getValue();
    }

    @Override
    public String getName() {
        return this.principalName;
    }

    @Override
    public Object getPrincipal() {
        return this.principalName;
    }
}
