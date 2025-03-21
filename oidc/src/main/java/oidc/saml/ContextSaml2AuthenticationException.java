package oidc.saml;

import oidc.model.AuthenticationRequest;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;

public class ContextSaml2AuthenticationException extends Saml2AuthenticationException {

    private final AuthenticationRequest authenticationRequest;

    public ContextSaml2AuthenticationException(AuthenticationRequest authenticationRequest, String description) {
        super(new Saml2Error(Saml2ErrorCodes.INVALID_ASSERTION, description));
        this.authenticationRequest = authenticationRequest;
    }

    public AuthenticationRequest getAuthenticationRequest() {
        return authenticationRequest;
    }
}
