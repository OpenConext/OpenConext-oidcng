package oidc.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import lombok.SneakyThrows;
import oidc.endpoints.AuthorizationEndpoint;
import oidc.log.MDCContext;
import oidc.manage.ServiceProviderTranslation;
import oidc.model.OpenIDClient;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.secure.JWTRequest;
import org.apache.commons.io.IOUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.springframework.core.io.ClassPathResource;
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
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ConfigurableSamlAuthenticationRequestFilter extends SamlAuthenticationRequestFilter implements URLCoding {

    private final PortResolverImpl portResolver;
    private final AuthenticationRequestRepository authenticationRequestRepository;
    private final OpenIDClientRepository openIDClientRepository;
    private final ObjectMapper objectMapper;

    static String REDIRECT_URI_VALID = "REDIRECT_URI_VALID";

    public static String AUTHENTICATION_SUCCESS_QUERY_PARAMETER = "authentication_success";

    public ConfigurableSamlAuthenticationRequestFilter(SamlProviderProvisioning<ServiceProviderService> provisioning,
                                                       SamlRequestMatcher samlRequestMatcher,
                                                       AuthenticationRequestRepository authenticationRequestRepository,
                                                       OpenIDClientRepository openIDClientRepository,
                                                       ObjectMapper objectMapper) {
        super(provisioning, samlRequestMatcher);
        this.openIDClientRepository = openIDClientRepository;
        this.authenticationRequestRepository = authenticationRequestRepository;
        this.portResolver = new PortResolverImpl();
        this.objectMapper = objectMapper;
    }

    @SneakyThrows
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (getRequestMatcher().matches(request) && (authentication == null || !authentication.isAuthenticated())) {
            /*
             * If we were expecting a valid authentication, but cookies are not supported we fail-fast
             */
            List<NameValuePair> params = URLEncodedUtils.parse(request.getQueryString(), Charset.defaultCharset());
            if (params.stream().anyMatch(pair -> AUTHENTICATION_SUCCESS_QUERY_PARAMETER.equals(pair.getName()))) {
                response.sendRedirect("/feedback/no-session");
                return;
            }
            validateAuthorizationRequest(request);

            ServiceProviderService provider = getProvisioning().getHostedProvider();
            IdentityProviderMetadata idp = provider.getRemoteProviders().get(0);
            AuthenticationRequest authenticationRequest = provider.authenticationRequest(idp);
            authenticationRequest = enhanceAuthenticationRequest(provider, request, authenticationRequest);
            saveAuthenticationRequestUrl(request, authenticationRequest);

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

    @Override
    protected String getRelayState(ServiceProviderService provider, HttpServletRequest request) {
        String acrValues = request.getParameter("acr_values");
        String clientId = request.getParameter("client_id");
        return new RelayState(clientId, acrValues).toJson(objectMapper);
    }

    private AuthenticationRequest enhanceAuthenticationRequest(ServiceProviderService provider,
                                                               HttpServletRequest request,
                                                               AuthenticationRequest authenticationRequest) throws ParseException {
        String clientId = RelayState.from(getRelayState(provider, request), objectMapper).getClientId();

        if (StringUtils.hasText(clientId)) {
            String entityId = ServiceProviderTranslation.translateClientId(clientId);
            authenticationRequest.setScoping(new Scoping(new ArrayList<>(), Collections.singletonList(entityId), 1));
        }
        String prompt = AuthorizationEndpoint.validatePrompt(request);

        authenticationRequest.setForceAuth(prompt != null && prompt.contains("login"));

        /**
         * Based on the ongoing discussion with the certification committee
         * authenticationRequest.setPassive("none".equals(prompt));
         */
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
        String loginHint = request.getParameter("login_hint");
        if (StringUtils.hasText(loginHint)) {
            Scoping scoping = authenticationRequest.getScoping();
            if (scoping == null) {
                authenticationRequest.setScoping(new Scoping(new ArrayList<>(), Collections.emptyList(), 0));
            }
            List<String> idpList = authenticationRequest.getScoping().getIdpList();
            loginHint = decode(loginHint);
            Stream.of(loginHint.split(",")).map(String::trim).filter(this::isValidURI).forEach(idpEntityId -> idpList.add(idpEntityId.trim()));
        }
        return authenticationRequest;
    }

    private boolean isValidURI(String uri) {
        try {
            new URI(uri);
            return true;
        } catch (URISyntaxException e) {
            return false;
        }

    }

    private void saveAuthenticationRequestUrl(HttpServletRequest request, AuthenticationRequest authenticationRequest) {
        String id = authenticationRequest.getId();
        //EB also has a 1 hour validity
        LocalDateTime ldt = LocalDateTime.now().plusHours(1L);
        Date expiresIn = Date.from(ldt.atZone(ZoneId.systemDefault()).toInstant());
        SavedRequest savedRequest = new DefaultSavedRequest(request, portResolver);
        authenticationRequestRepository.insert(
                new oidc.model.AuthenticationRequest(id, expiresIn, savedRequest.getRedirectUrl())
        );
    }

    private void validateAuthorizationRequest(HttpServletRequest request) throws IOException {
        try {
            AuthorizationRequest authorizationRequest = AuthorizationRequest.parse(ServletUtils.createHTTPRequest(request));
            ClientID clientID = authorizationRequest.getClientID();
            if (clientID != null) {
                MDCContext.mdcContext("action", "Authorization", "clientId", clientID.getValue());

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
