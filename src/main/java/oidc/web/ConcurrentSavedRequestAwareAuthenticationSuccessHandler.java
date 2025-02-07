package oidc.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import oidc.model.AuthenticationRequest;
import oidc.repository.AuthenticationRequestRepository;
import oidc.user.OidcSamlAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;

public class ConcurrentSavedRequestAwareAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private AuthenticationRequestRepository authenticationRequestRepository;

    public ConcurrentSavedRequestAwareAuthenticationSuccessHandler(AuthenticationRequestRepository authenticationRequestRepository) {
        this.authenticationRequestRepository = authenticationRequestRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        OidcSamlAuthentication samlAuthentication = (OidcSamlAuthentication) authentication;
        AuthenticationRequest authenticationRequest = authenticationRequestRepository.findById(samlAuthentication.getAuthenticationRequestID())
                .orElseThrow(() -> new IllegalArgumentException("No Authentication Request found for ID: " + samlAuthentication.getAuthenticationRequestID()));
        String originalRequestUrl = authenticationRequest.getOriginalRequestUrl();
        getRedirectStrategy().sendRedirect(request, response, originalRequestUrl);
    }
}
