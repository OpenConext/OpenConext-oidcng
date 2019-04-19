package oidc.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ConfigurableSamlAuthenticationRequestFilter extends SamlAuthenticationRequestFilter {

    private SamlRequestMatcher samlRequestMatcher;
    private SamlProviderProvisioning<ServiceProviderService> provisioning;

    public ConfigurableSamlAuthenticationRequestFilter(SamlProviderProvisioning<ServiceProviderService> provisioning,
                                                       SamlRequestMatcher samlRequestMatcher) {
        super(provisioning, samlRequestMatcher);
        //TODO Wait for pull request to be accepted to increase portability
        this.provisioning = provisioning;
        this.samlRequestMatcher = samlRequestMatcher;
    }

    @Override
    protected String getRelayState(ServiceProviderService provider, HttpServletRequest request) {
        return request.getParameter("client_id");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (samlRequestMatcher.matches(request) && (authentication == null || !authentication.isAuthenticated())) {
            ServiceProviderService provider = provisioning.getHostedProvider();
            IdentityProviderMetadata idp = provider.getRemoteProviders().get(0);
            AuthenticationRequest authenticationRequest = provider.authenticationRequest(idp);
            sendAuthenticationRequest(
                    provider,
                    request,
                    response,
                    authenticationRequest,
                    authenticationRequest.getDestination()
            );
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
