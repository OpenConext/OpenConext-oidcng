package oidc.config;

import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;

import java.time.Clock;

public class ScopedOpenSamlImplementation extends OpenSamlImplementation {

    public ScopedOpenSamlImplementation(Clock time) {
        super(time);
    }

    //can be removed when https://github.com/spring-projects/spring-security-saml/pull/435/files is accepted / merged
    protected AuthnRequest internalToXml(AuthenticationRequest request) {
        AuthnRequest auth = buildSAMLObject(AuthnRequest.class);
        auth.setID(request.getId());
        auth.setVersion(SAMLVersion.VERSION_20);
        auth.setIssueInstant(request.getIssueInstant());
        auth.setForceAuthn(request.isForceAuth());
        auth.setIsPassive(request.isPassive());
        auth.setProtocolBinding(request.getBinding().toString());
        auth.setAssertionConsumerServiceURL(request.getAssertionConsumerService().getLocation());
        auth.setDestination(request.getDestination().getLocation());
        auth.setNameIDPolicy(getNameIDPolicy(request.getNameIdPolicy()));
        auth.setRequestedAuthnContext(getRequestedAuthenticationContext(request));
        auth.setIssuer(toIssuer(request.getIssuer()));
        auth.setScoping(getScoping(request.getScoping()));
        if (request.getSigningKey() != null) {
            this.signObject(auth, request.getSigningKey(), request.getAlgorithm(), request.getDigest());
        }
        return auth;
    }

}
