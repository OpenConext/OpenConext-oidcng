package oidc.saml;

import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;

//@TODO: potentially obsolete in Spring Boot 3
public class AuthenticationRequestContextResolver {//implements Saml2AuthenticationRequestContextResolver {

    private final RelyingPartyRegistration registration;

    public AuthenticationRequestContextResolver(RelyingPartyRegistration registration) {
        this.registration = registration;
    }

//    @Override
    public AbstractSaml2AuthenticationRequest resolve(HttpServletRequest request) {
        return new CustomSaml2AuthenticationRequestContext(registration, request).getAuthenticationRequest();
    }
}
