package oidc.web;

import oidc.manage.ServiceProviderTranslation;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Scoping;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class ConfigurableSamlAuthenticationRequestFilter extends SamlAuthenticationRequestFilter {

    private RequestCache requestCache = new HttpSessionRequestCache();

    public ConfigurableSamlAuthenticationRequestFilter(SamlProviderProvisioning<ServiceProviderService> provisioning,
                                                       SamlRequestMatcher samlRequestMatcher) {
        super(provisioning, samlRequestMatcher);
    }

    @Override
    protected String getRelayState(ServiceProviderService provider, HttpServletRequest request) {
        return request.getParameter("client_id");
    }

    protected AuthenticationRequest enhanceAuthenticationRequest(ServiceProviderService provider, HttpServletRequest request,
                                                                 AuthenticationRequest authenticationRequest) {
        String clientId = getRelayState(provider, request);
        if (StringUtils.hasText(clientId)) {
            String entityId = ServiceProviderTranslation.translateClientId(clientId);
            authenticationRequest.setScoping(new Scoping(null, Collections.singletonList(entityId), 1));
        }
        String prompt = request.getParameter("prompt");
        if ("login".equals(prompt)) {
            authenticationRequest.setForceAuth(Boolean.TRUE);
        }
        return authenticationRequest;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (getRequestMatcher().matches(request) && (authentication == null || !authentication.isAuthenticated())) {
            ServiceProviderService provider = getProvisioning().getHostedProvider();
            IdentityProviderMetadata idp = provider.getRemoteProviders().get(0);
            AuthenticationRequest authenticationRequest = provider.authenticationRequest(idp);
            authenticationRequest = enhanceAuthenticationRequest(provider, request, authenticationRequest);
            requestCache.saveRequest(request, response);
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
