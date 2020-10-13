package oidc.saml;

import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import java.util.UUID;

import static org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding.REDIRECT;


public class AuthnRequestConverter implements
        Converter<Saml2AuthenticationRequestContext, AuthnRequest> {

    private final AuthnRequestBuilder authnRequestBuilder;
    private final IssuerBuilder issuerBuilder;

    public AuthnRequestConverter(AuthnRequestBuilder authnRequestBuilder, IssuerBuilder issuerBuilder) {
        this.authnRequestBuilder = authnRequestBuilder;
        this.issuerBuilder = issuerBuilder;
    }

    @Override
    public AuthnRequest convert(Saml2AuthenticationRequestContext ctx) {
        CustomSaml2AuthenticationRequestContext context = (CustomSaml2AuthenticationRequestContext) ctx;
        RelyingPartyRegistration relyingParty = context.getRelyingParty();

        AuthnRequest authnRequest = this.authnRequestBuilder.buildObject();
        authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setForceAuthn(Boolean.FALSE);
        authnRequest.setIsPassive(Boolean.FALSE);
        authnRequest.setProtocolBinding(REDIRECT.getUrn());

        Issuer issuer = this.issuerBuilder.buildObject();
        issuer.setValue(relyingParty.getEntityId());
        authnRequest.setIssuer(issuer);
        authnRequest.setDestination(context.getDestination());
        authnRequest.setAssertionConsumerServiceURL(context.getAssertionConsumerServiceUrl());

        return authnRequest;
    }
}
