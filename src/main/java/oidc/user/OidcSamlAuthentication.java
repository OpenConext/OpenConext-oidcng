package oidc.user;

import lombok.Getter;
import lombok.Setter;
import oidc.model.User;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;

@Getter
public class OidcSamlAuthentication extends DefaultSamlAuthentication {

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
