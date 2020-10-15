package oidc.saml;

import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;

import javax.servlet.http.HttpServletRequest;

public class AuthenticationRequestContextResolver implements Saml2AuthenticationRequestContextResolver {

    private RelyingPartyRegistration registration;

    public AuthenticationRequestContextResolver(RelyingPartyRegistration registration) {
        this.registration = registration;
    }

    @Override
    public Saml2AuthenticationRequestContext resolve(HttpServletRequest request) {
        return new CustomSaml2AuthenticationRequestContext(registration, request);
    }
}
