package oidc.web;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import oidc.endpoints.AuthorizationEndpoint;
import oidc.exceptions.UnsupportedPromptValueException;
import oidc.manage.ServiceProviderTranslation;
import oidc.model.OpenIDClient;
import oidc.repository.OpenIDClientRepository;
import oidc.secure.JWTRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.RequestedAuthenticationContext;
import org.springframework.security.saml.saml2.authentication.Scoping;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class ConfigurableSamlAuthenticationRequestFilter extends SamlAuthenticationRequestFilter {

    private RequestCache requestCache = new HttpSessionRequestCache();
    private OpenIDClientRepository openIDClientRepository;

    static String REDIRECT_URI_VALID = "REDIRECT_URI_VALID";

    public ConfigurableSamlAuthenticationRequestFilter(SamlProviderProvisioning<ServiceProviderService> provisioning,
                                                       SamlRequestMatcher samlRequestMatcher,
                                                       OpenIDClientRepository openIDClientRepository) {
        super(provisioning, samlRequestMatcher);
        this.openIDClientRepository = openIDClientRepository;
    }

    @Override
    protected String getRelayState(ServiceProviderService provider, HttpServletRequest request) {
        return request.getParameter("client_id");
    }

    private AuthenticationRequest enhanceAuthenticationRequest(ServiceProviderService provider,
                                                               HttpServletRequest request,
                                                               AuthenticationRequest authenticationRequest) {
        String clientId = getRelayState(provider, request);
        if (StringUtils.hasText(clientId)) {
            String entityId = ServiceProviderTranslation.translateClientId(clientId);
            authenticationRequest.setScoping(new Scoping(null, Collections.singletonList(entityId), 1));
        }
        String prompt = AuthorizationEndpoint.validatePrompt(request);

        authenticationRequest.setForceAuth("login".equals(prompt));
        if (!authenticationRequest.isForceAuth() && StringUtils.hasText(request.getParameter("max_age"))) {
            authenticationRequest.setForceAuth(true);
        }
        String acrValues = request.getParameter("acr_values");
        if (StringUtils.hasText(acrValues)) {
            List<ACR> acrList = Arrays.stream(acrValues.split(" ")).map(ACR::new).collect(Collectors.toList());
            parseAcrValues(authenticationRequest, acrList);
        }
        String requestP = request.getParameter("request");
        String requestUrlP = request.getParameter("request_uri");
        if (StringUtils.hasText(requestP) || StringUtils.hasText(requestUrlP)) {
            OpenIDClient openIDClient = openIDClientRepository.findByClientId(clientId);
            try {
                com.nimbusds.openid.connect.sdk.AuthenticationRequest authRequest =
                        com.nimbusds.openid.connect.sdk.AuthenticationRequest.parse(ServletUtils.createHTTPRequest(request));
                authRequest = JWTRequest.parse(authRequest, openIDClient);
                List<ACR> acrValuesObjects = authRequest.getACRValues();
                parseAcrValues(authenticationRequest, acrValuesObjects);
                Prompt authRequestPrompt = authRequest.getPrompt();
                prompt = AuthorizationEndpoint.validatePrompt(authRequestPrompt);
                if (!authenticationRequest.isForceAuth() && authRequest.getMaxAge() > -1) {
                    authenticationRequest.setForceAuth(true);
                }
                if (!authenticationRequest.isForceAuth() && prompt != null) {
                    authenticationRequest.setForceAuth(prompt.contains("login"));
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return authenticationRequest;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (getRequestMatcher().matches(request) && (authentication == null || !authentication.isAuthenticated())) {

            validateAuthorizationRequest(request);

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

    private void validateAuthorizationRequest(HttpServletRequest request) throws IOException {
        try {
            AuthorizationRequest authorizationRequest = AuthorizationRequest.parse(ServletUtils.createHTTPRequest(request));
            ClientID clientID = authorizationRequest.getClientID();
            if (clientID != null) {
                OpenIDClient openIDClient = openIDClientRepository.findByClientId(clientID.getValue());
                AuthorizationEndpoint.validateRedirectionURI(authorizationRequest, openIDClient);

                request.setAttribute(REDIRECT_URI_VALID, true);

                AuthorizationEndpoint.validateScopes(authorizationRequest, openIDClient);
                AuthorizationEndpoint.validateGrantType(authorizationRequest, openIDClient);
            }
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private void parseAcrValues(AuthenticationRequest authenticationRequest, List<ACR> acrValuesObjects) {
        if (!CollectionUtils.isEmpty(acrValuesObjects)) {

            authenticationRequest.setAuthenticationContextClassReferences(
                    acrValuesObjects.stream()
                            .map(acrValue -> AuthenticationContextClassReference.fromUrn(acrValue.getValue()))
                            .collect(Collectors.toList()));
            authenticationRequest.setRequestedAuthenticationContext(RequestedAuthenticationContext.exact);
        }
    }

}
