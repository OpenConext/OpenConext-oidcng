package oidc.saml;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.http.HttpServletRequest;

@Getter
public class CustomSaml2AuthenticationRequestContext extends Saml2AuthenticationRequestContext {

    private final RequestCache requestCache = new HttpSessionRequestCache();

    private final SavedRequest savedRequest;
    private final HttpServletRequest request;

    public CustomSaml2AuthenticationRequestContext(RelyingPartyRegistration relyingPartyRegistration, HttpServletRequest request) {
        super(relyingPartyRegistration, relyingPartyRegistration.getEntityId(), relyingPartyRegistration.getAssertionConsumerServiceLocation(), request.getParameter("RelayState"));
        this.savedRequest = requestCache.getRequest(request, null);
        this.request = request;
    }
}
