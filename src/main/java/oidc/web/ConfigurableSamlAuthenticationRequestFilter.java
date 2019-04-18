package oidc.web;

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

import static org.springframework.util.StringUtils.hasText;

public class ConfigurableSamlAuthenticationRequestFilter extends SamlAuthenticationRequestFilter {

    private SamlProviderProvisioning<ServiceProviderService> provisioning;

    public ConfigurableSamlAuthenticationRequestFilter(SamlProviderProvisioning<ServiceProviderService> provisioning) {
        super(provisioning, new SamlRequestMatcher(provisioning, "discovery", false));
        this.provisioning = provisioning;
    }

    @Override
    protected String getRelayState(ServiceProviderService provider, HttpServletRequest request) {
        return request.getParameter("client_id");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String idpIdentifier = request.getParameter("commence");
        if (hasText(idpIdentifier)) {
            ServiceProviderService provider = provisioning.getHostedProvider();
            IdentityProviderMetadata idp = provider.getRemoteProviders().get(0);
//            IdentityProviderMetadata idp = getIdentityProvider(provider, idpIdentifier);
            AuthenticationRequest authenticationRequest = provider.authenticationRequest(idp);
            sendAuthenticationRequest(
                    provider,
                    request,
                    response,
                    authenticationRequest,
                    authenticationRequest.getDestination()
            );
        }
        else {
            filterChain.doFilter(request, response);
        }
    }
}
