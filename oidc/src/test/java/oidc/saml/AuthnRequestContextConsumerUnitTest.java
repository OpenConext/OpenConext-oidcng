package oidc.saml;

import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import oidc.exceptions.CookiesNotSupportedException;
import oidc.exceptions.JWTRequestURIMismatchException;
import oidc.model.OpenIDClient;
import oidc.model.Scope;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.secure.SignedJWTTest;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.IDPEntry;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml5AuthenticationRequestResolver;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.RequestCache;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static oidc.model.EntityType.OAUTH_RS;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthnRequestContextConsumerUnitTest extends AbstractSamlUnitTest implements SignedJWTTest {

    private final OpenIDClientRepository openIDClientRepository = mock(OpenIDClientRepository.class);
    private final AuthenticationRequestRepository authenticationRequestRepository = mock(AuthenticationRequestRepository.class);
    private final RequestCache requestCache = mock(RequestCache.class);
    private final XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);

    private AuthnRequestContextConsumer subject;

    @Before
    public void beforeTest() {
        subject = new AuthnRequestContextConsumer(openIDClientRepository, authenticationRequestRepository, requestCache);
    }

    @Test
    public void testSaml() throws Exception {
        OpenIDClient openIDClient = new OpenIDClient("clientId", singletonList("http://redirect"), singletonList(new Scope("openid")), singletonList("authorization_code"));
        String cert = readFile("keys/certificate.crt");
        setCertificateFields(openIDClient, cert, null, null);
        when(openIDClientRepository.findOptionalByClientId("mock_sp")).thenReturn(Optional.of(openIDClient));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "http://localhost/oidc/authorize");
        request.addParameter("client_id", "mock_sp");
        request.addParameter("response_type", "code");
        request.addParameter("acr_values", "http://loa1");
        request.addParameter("prompt", "login");
        request.addParameter("login_hint", "https://idp,https://idp2,tata@ex.org");

        String keyID = getCertificateKeyIDFromCertificate(cert);
        SignedJWT signedJWT = signedJWT(openIDClient.getClientId(), keyID, openIDClient.getRedirectUrls().get(0));
        request.addParameter("request", signedJWT.serialize());

        when(requestCache.getRequest(any(HttpServletRequest.class), any()))
                .thenReturn(new DefaultSavedRequest(request));

        AuthnRequest authnRequest = getAuthnRequest();

        OpenSaml5AuthenticationRequestResolver.AuthnRequestContext ctx =
                new OpenSaml5AuthenticationRequestResolver.AuthnRequestContext(request, relyingParty, authnRequest);

        subject.accept(ctx);

        assertTrue(authnRequest.isForceAuthn());
        assertEquals("loa1", authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).getURI());
        List<IDPEntry> idpEntrys = authnRequest.getScoping().getIDPList().getIDPEntrys();
        assertEquals(2, idpEntrys.size());
        assertEquals("https://idp", idpEntrys.get(0).getProviderID());
        assertEquals("https://idp2", idpEntrys.get(1).getProviderID());
    }

    private AuthnRequest getAuthnRequest() {
        AuthnRequestBuilder authnRequestBuilder = (AuthnRequestBuilder) registry.getBuilderFactory()
                .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest authnRequest = authnRequestBuilder.buildObject();
        return authnRequest;
    }

    @Test
    public void testJWTRequestURIMismatch() {
        OpenIDClient openIDClient = new OpenIDClient(Map.of(
                "type", OAUTH_RS.getType(),
                "data", Map.of("entityid", "mock_sp",
                        "metaDataFields",
                        Map.of("oidc:jwtRequestUri", "http://valid.url",
                                "redirectUrls", List.of("http://localhost:8080")))));
        when(openIDClientRepository.findOptionalByClientId("mock_sp")).thenReturn(Optional.of(openIDClient));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "http://localhost/oidc/authorize");
        request.addParameter("client_id", "mock_sp");
        request.addParameter("response_type", "code");
        request.addParameter("request_uri", "http://invalid_url");

        HttpServletRequest servletRequest = new MockHttpServletRequest();

        when(requestCache.getRequest(any(HttpServletRequest.class), any()))
                .thenReturn(new DefaultSavedRequest(request));
        AuthnRequest authnRequest = getAuthnRequest();

        OpenSaml5AuthenticationRequestResolver.AuthnRequestContext ctx =
                new OpenSaml5AuthenticationRequestResolver.AuthnRequestContext(request, relyingParty, authnRequest);

        assertThrows(JWTRequestURIMismatchException.class, () -> subject.accept(ctx));
    }

    @Test
    public void testSamlForceAuthn() throws Exception {
        OpenIDClient openIDClient = new OpenIDClient("clientId", singletonList("http://redirect"), singletonList(new Scope("openid")), singletonList("authorization_code"));
        when(openIDClientRepository.findOptionalByClientId("mock_sp")).thenReturn(Optional.of(openIDClient));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "http://localhost/oidc/authorize");

        request.addParameter("max_age", "-1");
        request.addParameter("response_type", "code");
        request.addParameter("client_id", "mock_sp");

        when(requestCache.getRequest(any(HttpServletRequest.class), any()))
                .thenReturn(new DefaultSavedRequest(request));

        AuthnRequest authnRequest = getAuthnRequest();

        OpenSaml5AuthenticationRequestResolver.AuthnRequestContext ctx =
                new OpenSaml5AuthenticationRequestResolver.AuthnRequestContext(request, relyingParty, authnRequest);

        subject.accept(ctx);

        assertTrue(authnRequest.isForceAuthn());
    }

    @Test(expected = CookiesNotSupportedException.class)
    public void noCookies() {
        HttpServletRequest request = new MockHttpServletRequest();
        AuthnRequest authnRequest = getAuthnRequest();

        OpenSaml5AuthenticationRequestResolver.AuthnRequestContext ctx =
                new OpenSaml5AuthenticationRequestResolver.AuthnRequestContext(request, relyingParty, authnRequest);

        subject.accept(ctx);
    }

}
