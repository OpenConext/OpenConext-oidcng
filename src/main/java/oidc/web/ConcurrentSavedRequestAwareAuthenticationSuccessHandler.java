package oidc.web;

import oidc.model.AuthenticationRequest;
import oidc.repository.AuthenticationRequestRepository;
import oidc.user.OidcSamlAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//import static oidc.web.ConfigurableSamlAuthenticationRequestFilter.AUTHENTICATION_SUCCESS_QUERY_PARAMETER;

public class ConcurrentSavedRequestAwareAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private AuthenticationRequestRepository authenticationRequestRepository;

    public ConcurrentSavedRequestAwareAuthenticationSuccessHandler(AuthenticationRequestRepository authenticationRequestRepository) {
        this.authenticationRequestRepository = authenticationRequestRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        OidcSamlAuthentication samlAuthentication = (OidcSamlAuthentication) authentication;
        AuthenticationRequest authenticationRequest = authenticationRequestRepository.findById(samlAuthentication.getAuthenticationRequestID()).orElseThrow(
                () -> new IllegalArgumentException("No Authentication Request found for ID: " + samlAuthentication.getAuthenticationRequestID()));
        String originalRequestUrl = authenticationRequest.getOriginalRequestUrl();

        String append = originalRequestUrl.contains("?") ? "&" : "?";
        //To check if cookies are blocked
//        originalRequestUrl += (append + AUTHENTICATION_SUCCESS_QUERY_PARAMETER + "=" + true);
        //Redirect to authorize endpoint
        getRedirectStrategy().sendRedirect(request, response, originalRequestUrl);
    }
}
