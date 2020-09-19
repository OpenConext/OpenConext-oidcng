package oidc.web;

import oidc.TestUtils;
import oidc.model.AuthenticationRequest;
import oidc.repository.AuthenticationRequestRepository;
import oidc.user.OidcSamlAuthentication;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ConcurrentSavedRequestAwareAuthenticationSuccessHandlerTest implements TestUtils {

    private AuthenticationRequestRepository authenticationRequestRepository = mock(AuthenticationRequestRepository.class);

    private ConcurrentSavedRequestAwareAuthenticationSuccessHandler subject =
            new ConcurrentSavedRequestAwareAuthenticationSuccessHandler(authenticationRequestRepository);

//    @Test
//    public void onAuthenticationSuccess() throws IOException, ServletException {
//        MockHttpServletResponse response = new MockHttpServletResponse();
//        when(authenticationRequestRepository.findById("ID"))
//                .thenReturn(Optional.of(new AuthenticationRequest("ID", new Date(), "http://localhost")));
//        subject.onAuthenticationSuccess(new MockHttpServletRequest(), response, new OidcSamlAuthentication(FakeSamlAuthenticationFilter.getAssertion(),
//               FakeSamlAuthenticationFilter.getUser(objectMapper, new MockHttpServletRequest()),
//                "ID"));
//        assertEquals("http://localhost", response.getHeader("Location"));
//        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
//    }
//
//    @Test(expected = IllegalArgumentException.class)
//    public void onAuthenticationSuccessFailure() throws IOException, ServletException {
//        MockHttpServletResponse response = new MockHttpServletResponse();
//        when(authenticationRequestRepository.findById("ID"))
//                .thenReturn(Optional.empty());
//        subject.onAuthenticationSuccess(new MockHttpServletRequest(), response, new OidcSamlAuthentication(FakeSamlAuthenticationFilter.getAssertion(),
//                FakeSamlAuthenticationFilter.getUser(objectMapper, new MockHttpServletRequest()),
//                "ID"));
//    }
}