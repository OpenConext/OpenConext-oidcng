package oidc.saml;

import lombok.SneakyThrows;
import oidc.crypto.KeyGenerator;
import org.junit.Before;
import org.junit.BeforeClass;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public abstract class AbstractSamlUnitTest {

    protected static Saml2X509Credential saml2X509Credential;
    protected static PortResolver portResolver = new PortResolverImpl();
    protected static RelyingPartyRegistration relyingParty;

    @BeforeClass
    public static void beforeClass() {
        saml2X509Credential = getSigningCredential();
        OpenSamlInitializationService.initialize();

        relyingParty = RelyingPartyRegistration
                .withRegistrationId("oidcng")
                .entityId("entityID")
                .signingX509Credentials(c -> c.add(saml2X509Credential))
                .assertionConsumerServiceLocation("https://acs")
                .assertingPartyDetails(builder -> builder
                        .entityId("entityID")
                        .wantAuthnRequestsSigned(false)
                        .singleSignOnServiceLocation("https://sso").build())
                .build();
    }

    @SneakyThrows
    private static Saml2X509Credential getSigningCredential() {
        String[] keys = KeyGenerator.generateKeys();
        String pem = keys[0];
        String certificate = keys[1];
        PrivateKey privateKey = KeyGenerator.readPrivateKey(pem);
        byte[] certBytes = KeyGenerator.getDER(certificate);
        X509Certificate x509Certificate = KeyGenerator.getCertificate(certBytes);

        return new Saml2X509Credential(privateKey, x509Certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
    }


}
