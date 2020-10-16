package oidc.web;

import oidc.TestUtils;
import oidc.model.AuthenticationRequest;
import oidc.repository.AuthenticationRequestRepository;
import oidc.user.OidcSamlAuthentication;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ConcurrentSavedRequestAwareAuthenticationSuccessHandlerTest implements TestUtils {

    @Test
    public void onAuthenticationSuccess() throws IOException {
        AuthenticationRequestRepository authenticationRequestRepository = mock(AuthenticationRequestRepository.class);

        ConcurrentSavedRequestAwareAuthenticationSuccessHandler subject =
                new ConcurrentSavedRequestAwareAuthenticationSuccessHandler(authenticationRequestRepository);

        when(authenticationRequestRepository.findById(isNull()))
                .thenReturn(Optional.of(new AuthenticationRequest("ID", new Date(), "client_id", "http://localhost")));

        MockHttpServletResponse response = new MockHttpServletResponse();
        subject.onAuthenticationSuccess(new MockHttpServletRequest(), response, new OidcSamlAuthentication());

        assertEquals("http://localhost", response.getHeader("Location"));
        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
    }

}