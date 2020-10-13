package oidc.saml;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import javax.servlet.http.HttpServletRequest;

@Getter
public class CustomSaml2AuthenticationRequestContext extends Saml2AuthenticationRequestContext {

    private HttpServletRequest request;
    private RelyingPartyRegistration relyingParty;

    public CustomSaml2AuthenticationRequestContext(RelyingPartyRegistration relyingPartyRegistration, HttpServletRequest request) {
        super(relyingPartyRegistration, relyingPartyRegistration.getEntityId(), relyingPartyRegistration.getAssertionConsumerServiceLocation(), request.getParameter("RelayState"));
        this.relyingParty = relyingPartyRegistration;
        this.request = request;
    }
}
