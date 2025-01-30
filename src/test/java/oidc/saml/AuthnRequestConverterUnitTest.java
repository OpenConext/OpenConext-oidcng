package oidc.saml;

import com.nimbusds.jwt.SignedJWT;
import oidc.exceptions.CookiesNotSupportedException;
import oidc.exceptions.JWTRequestURIMismatchException;
import oidc.model.OpenIDClient;
import oidc.model.Scope;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.secure.SignedJWTTest;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.RequestCache;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static oidc.model.EntityType.OAUTH_RS;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthnRequestConverterUnitTest extends AbstractSamlUnitTest implements SignedJWTTest {

    private final OpenIDClientRepository openIDClientRepository = mock(OpenIDClientRepository.class);
    private final AuthenticationRequestRepository authenticationRequestRepository = mock(AuthenticationRequestRepository.class);
    private final RequestCache requestCache = mock(RequestCache.class);

    private AuthnRequestConverter subject;

    @Before
    public void beforeTest() throws Exception {
        subject = new AuthnRequestConverter(openIDClientRepository, authenticationRequestRepository, requestCache);
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
        request.addParameter("login_hint", "http://idp");

        String keyID = getCertificateKeyIDFromCertificate(cert);
        SignedJWT signedJWT = signedJWT(openIDClient.getClientId(), keyID, openIDClient.getRedirectUrls().get(0));
        request.addParameter("request", signedJWT.serialize());

        HttpServletRequest servletRequest = new MockHttpServletRequest();
        CustomSaml2AuthenticationRequestContext ctx = new CustomSaml2AuthenticationRequestContext(relyingParty, servletRequest);

        when(requestCache.getRequest(any(HttpServletRequest.class), any()))
                .thenReturn(new DefaultSavedRequest(request, portResolver));

        AuthnRequest authnRequest = subject.convert(ctx);

        assertTrue(authnRequest.isForceAuthn());
        assertEquals("loa1", authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).getURI());
        assertEquals("http://idp", authnRequest.getScoping().getIDPList().getIDPEntrys().get(0).getProviderID());
    }

    @Test
    public void testJWTRequestURIMismatch() throws Exception {
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
        CustomSaml2AuthenticationRequestContext ctx = new CustomSaml2AuthenticationRequestContext(relyingParty, servletRequest);

        when(requestCache.getRequest(any(HttpServletRequest.class), any()))
                .thenReturn(new DefaultSavedRequest(request, portResolver));
        assertThrows(JWTRequestURIMismatchException.class, () -> subject.convert(ctx));
    }

    @Test
    public void testSamlForceAuthn() throws Exception {
        OpenIDClient openIDClient = new OpenIDClient("clientId", singletonList("http://redirect"), singletonList(new Scope("openid")), singletonList("authorization_code"));
        when(openIDClientRepository.findOptionalByClientId("mock_sp")).thenReturn(Optional.of(openIDClient));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "http://localhost/oidc/authorize");

        request.addParameter("max_age", "-1");
        request.addParameter("response_type", "code");
        request.addParameter("client_id", "mock_sp");

        HttpServletRequest servletRequest = new MockHttpServletRequest();
        CustomSaml2AuthenticationRequestContext ctx = new CustomSaml2AuthenticationRequestContext(relyingParty, servletRequest);

        when(requestCache.getRequest(any(HttpServletRequest.class), any()))
                .thenReturn(new DefaultSavedRequest(request, portResolver));

        AuthnRequest authnRequest = subject.convert(ctx);
        assertTrue(authnRequest.isForceAuthn());
    }

    @Test(expected = CookiesNotSupportedException.class)
    public void noCookies() {
        HttpServletRequest servletRequest = new MockHttpServletRequest();
        CustomSaml2AuthenticationRequestContext ctx = new CustomSaml2AuthenticationRequestContext(relyingParty, servletRequest);
        subject.convert(ctx);
    }

}