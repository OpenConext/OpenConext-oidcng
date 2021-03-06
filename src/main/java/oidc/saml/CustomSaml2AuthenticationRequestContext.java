package oidc.saml;

import lombok.Getter;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import javax.servlet.http.HttpServletRequest;

@Getter
public class CustomSaml2AuthenticationRequestContext extends Saml2AuthenticationRequestContext {

    private final HttpServletRequest request;

    public CustomSaml2AuthenticationRequestContext(RelyingPartyRegistration relyingPartyRegistration, HttpServletRequest request) {
        super(relyingPartyRegistration, relyingPartyRegistration.getEntityId(),
                relyingPartyRegistration.getAssertionConsumerServiceLocation(), request.getParameter("RelayState"));
        this.request = request;
    }
}
