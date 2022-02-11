package oidc.web;

import oidc.model.OpenIDClient;
import oidc.repository.OpenIDClientRepository;
import oidc.saml.ContextSaml2AuthenticationException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.http.HttpSession;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static oidc.saml.AuthnRequestConverter.REDIRECT_URI_VALID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RedirectAuthenticationFailureHandlerTest {

    private RequestCache requestCache = new HttpSessionRequestCache();
    private OpenIDClientRepository openIDClientRepository = mock(OpenIDClientRepository.class);
    private RedirectAuthenticationFailureHandler subject = new RedirectAuthenticationFailureHandler(openIDClientRepository);

    @Test
    void onAuthenticationFailureSaml2AuthenticationException() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThrows(Saml2AuthenticationException.class, () -> {
            Saml2AuthenticationException exception = new Saml2AuthenticationException(new Saml2Error("code", "description"));
            subject.onAuthenticationFailure(request, null, exception);
        });
    }

    @Test
    void onAuthenticationFailureSavedRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("client_id", "client_id");
        request.addParameter("redirect_uri", "http://redirect");

        HttpSession session = request.getSession(true);
        PortResolver portResolver = new PortResolverImpl();
        SavedRequest savedRequest = new DefaultSavedRequest(request, portResolver);
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);
        OpenIDClient openIdClient = new OpenIDClient("client_id", singletonList("http://redirect"), emptyList(), emptyList());

        when(openIDClientRepository.findOptionalByClientId("client_id")).thenReturn(Optional.of(openIdClient));

        assertThrows(AccountStatusException.class, () ->
                subject.onAuthenticationFailure(request, null, new DisabledException("Not ok")));
        assertEquals(true, request.getAttribute(REDIRECT_URI_VALID));
    }

    @Test
    void onAuthenticationFailureRequestCache() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("client_id", "client_id");
        request.addParameter("redirect_uri", "http://redirect");

        requestCache.saveRequest(request, null);
        OpenIDClient openIdClient = new OpenIDClient("client_id", singletonList("http://redirect"), emptyList(), emptyList());

        when(openIDClientRepository.findOptionalByClientId("client_id")).thenReturn(Optional.of(openIdClient));

        assertThrows(AccountStatusException.class, () ->
                subject.onAuthenticationFailure(request, null, new DisabledException("Not ok")));
        assertEquals(true, request.getAttribute(REDIRECT_URI_VALID));
    }

    @Test
    void onAuthenticationFailureContextRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThrows(ContextSaml2AuthenticationException.class, () ->
                subject.onAuthenticationFailure(request, null, new ContextSaml2AuthenticationException(null, "Not ok")));
        assertEquals(true, request.getAttribute(REDIRECT_URI_VALID));
    }
}