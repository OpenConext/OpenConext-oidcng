package oidc.saml;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

@Getter
public class CustomSaml2AuthenticationRequestContext extends Saml2AuthenticationToken {

    private final HttpServletRequest request;

    public CustomSaml2AuthenticationRequestContext(RelyingPartyRegistration relyingPartyRegistration, HttpServletRequest request) {
        super(relyingPartyRegistration, relyingPartyRegistration.getEntityId(), null);
        this.request = request;
    }
}
