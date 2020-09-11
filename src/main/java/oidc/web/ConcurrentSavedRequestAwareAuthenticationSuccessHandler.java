package oidc.web;

import oidc.model.AuthenticationRequest;
import oidc.repository.AuthenticationRequestRepository;
import oidc.user.OidcSamlAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static oidc.web.ConfigurableSamlAuthenticationRequestFilter.AUTHENTICATION_REQUEST_ID;

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
        //To be cookie-less
        originalRequestUrl += (append + AUTHENTICATION_REQUEST_ID + "=" + authenticationRequest.getId());
        authenticationRequest.setUserId(samlAuthentication.getUser().getId());
        authenticationRequestRepository.save(authenticationRequest);
        //Redirect to authorize endpoint
        getRedirectStrategy().sendRedirect(request, response, originalRequestUrl);
    }
}
