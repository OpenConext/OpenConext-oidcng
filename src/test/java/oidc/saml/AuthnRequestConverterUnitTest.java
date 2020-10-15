package oidc.saml;

import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import oidc.crypto.KeyGenerator;
import oidc.model.OpenIDClient;
import oidc.model.Scope;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.secure.SignedJWTTest;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.test.util.ReflectionTestUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthnRequestConverterUnitTest implements SignedJWTTest {

    private OpenIDClientRepository openIDClientRepository = mock(OpenIDClientRepository.class);
    private AuthenticationRequestRepository authenticationRequestRepository = mock(AuthenticationRequestRepository.class);
    private RequestCache requestCache = mock(RequestCache.class);

    private static Saml2X509Credential saml2X509Credential;
    private static PortResolver portResolver = new PortResolverImpl();

    private AuthnRequestConverter subject = new AuthnRequestConverter(openIDClientRepository, authenticationRequestRepository, requestCache);

    @BeforeClass
    public static void beforeClass() {
        saml2X509Credential = getSigningCredential();
        OpenSamlInitializationService.initialize();
    }

    @Before
    public void before() throws Exception {
        OpenIDClient openIDClient = new OpenIDClient("clientId", singletonList("http://redirect"), singletonList(new Scope("openid")), singletonList("authorization_code"));
        String cert = readFile("keys/certificate.crt");
        setCertificateFields(openIDClient, cert, null, null);
        when(openIDClientRepository.findByClientId("mock_sp")).thenReturn(openIDClient);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "http://localhost/oidc/authorize");
        request.addParameter("client_id", "mock_sp");
        request.addParameter("response_type", "code");
        request.addParameter("acr_values", "http://loa1");
        request.addParameter("prompt", "login");
        request.addParameter("login_hint", "http://idp");

        String keyID = getCertificateKeyIDFromCertificate(cert);
        SignedJWT signedJWT = signedJWT(openIDClient.getClientId(), keyID, openIDClient.getRedirectUrls().get(0));
        request.addParameter("request", signedJWT.serialize());

        when(requestCache.getRequest(any(HttpServletRequest.class), any()))
                .thenReturn(new DefaultSavedRequest(request, portResolver));
    }

    @Test
    public void testSaml() throws IOException {
        RelyingPartyRegistration relyingParty = RelyingPartyRegistration
                .withRegistrationId("oidcng")
                .entityId("entityID")
                .signingX509Credentials(c -> c.add(saml2X509Credential))
                .assertionConsumerServiceLocation("https://acs")
                .assertingPartyDetails(builder -> builder
                        .entityId("entityID")
                        .wantAuthnRequestsSigned(false)
                        .singleSignOnServiceLocation("https://sso").build())
                .build();
        HttpServletRequest request = new MockHttpServletRequest();
        CustomSaml2AuthenticationRequestContext ctx = new CustomSaml2AuthenticationRequestContext(relyingParty, request);
        AuthnRequest authnRequest = subject.convert(ctx);

        assertTrue(authnRequest.isForceAuthn());
        assertEquals("loa1", authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).getAuthnContextClassRef());
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