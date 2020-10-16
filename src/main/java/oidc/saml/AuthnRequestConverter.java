package oidc.saml;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import lombok.SneakyThrows;
import oidc.endpoints.AuthorizationEndpoint;
import oidc.exceptions.CookiesNotSupportedException;
import oidc.log.MDCContext;
import oidc.manage.ServiceProviderTranslation;
import oidc.model.OpenIDClient;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.secure.JWTRequest;
import oidc.web.URLCoding;
import org.joda.time.DateTime;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.RequesterID;
import org.opensaml.saml.saml2.core.Scoping;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.RequesterIDBuilder;
import org.opensaml.saml.saml2.core.impl.ScopingBuilder;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding.REDIRECT;


public class AuthnRequestConverter implements
        Converter<Saml2AuthenticationRequestContext, AuthnRequest>, URLCoding {

    public final static String REDIRECT_URI_VALID = "REDIRECT_URI_VALID";

    private final OpenIDClientRepository openIDClientRepository;
    private final AuthenticationRequestRepository authenticationRequestRepository;
    private final XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
    private final RequestCache requestCache;

    public AuthnRequestConverter(OpenIDClientRepository openIDClientRepository,
                                 AuthenticationRequestRepository authenticationRequestRepository,
                                 RequestCache requestCache) {

        this.openIDClientRepository = openIDClientRepository;
        this.authenticationRequestRepository = authenticationRequestRepository;
        this.requestCache = requestCache;
    }

    @SneakyThrows
    @Override
    public AuthnRequest convert(Saml2AuthenticationRequestContext ctx) {
        CustomSaml2AuthenticationRequestContext context = (CustomSaml2AuthenticationRequestContext) ctx;
        HttpServletRequest request = context.getRequest();
        SavedRequest savedRequest = requestCache.getRequest(request, null);

        if (savedRequest == null) {
            throw new CookiesNotSupportedException();
        }

        Map<String, String[]> parameterMap = savedRequest.getParameterMap();
        Map<String, List<String>> parameters = parameterMap.keySet().stream()
                .collect(Collectors.toMap(key -> key, key -> Arrays.asList(parameterMap.get(key))));
        AuthorizationRequest authorizationRequest = AuthorizationRequest.parse(parameters);

        validateAuthorizationRequest(authorizationRequest, request);

        RelyingPartyRegistration relyingParty = context.getRelyingPartyRegistration();
        AuthnRequestBuilder authnRequestBuilder = (AuthnRequestBuilder) registry.getBuilderFactory()
                .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest authnRequest = authnRequestBuilder.buildObject();
        authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setIsPassive(Boolean.FALSE);
        authnRequest.setProtocolBinding(REDIRECT.getUrn());

        IssuerBuilder issuerBuilder = (IssuerBuilder) registry.getBuilderFactory()
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(relyingParty.getEntityId());
        authnRequest.setIssuer(issuer);
        authnRequest.setDestination(context.getDestination());
        authnRequest.setAssertionConsumerServiceURL(context.getAssertionConsumerServiceUrl());


        saveAuthenticationRequestUrl(savedRequest, authnRequest, authorizationRequest.getClientID());
        enhanceAuthenticationRequest(authnRequest, parameters);
        return authnRequest;
    }

    @SneakyThrows
    private void validateAuthorizationRequest(AuthorizationRequest authorizationRequest, HttpServletRequest request) {
        ClientID clientID = authorizationRequest.getClientID();
        if (clientID != null) {
            MDCContext.mdcContext("action", "Authorization", "clientId", clientID.getValue());

            OpenIDClient openIDClient = openIDClientRepository.findByClientId(clientID.getValue());
            AuthorizationEndpoint.validateRedirectionURI(authorizationRequest, openIDClient);

            request.setAttribute(REDIRECT_URI_VALID, true);

            AuthorizationEndpoint.validateScopes(authorizationRequest, openIDClient);
            AuthorizationEndpoint.validateGrantType(authorizationRequest, openIDClient);
        }
    }

    private String param(String name, Map<String, List<String>> request) {
        List<String> values = request.get(name);
        return CollectionUtils.isEmpty(values) ? null : values.get(0);
    }

    private AuthnRequest enhanceAuthenticationRequest(AuthnRequest authnRequest,
                                                      Map<String, List<String>> request) throws ParseException {
        String clientId = param("client_id", request);

        if (StringUtils.hasText(clientId)) {
            String entityId = ServiceProviderTranslation.translateClientId(clientId);
            authnRequest.setScoping(getScoping(Arrays.asList(entityId)));
        }
        String prompt = AuthorizationEndpoint.validatePrompt(request);

        authnRequest.setForceAuthn(prompt != null && prompt.contains("login"));

        /**
         * Based on the ongoing discussion with the certification committee
         * authenticationRequest.setPassive("none".equals(prompt));
         */
        if (!authnRequest.isForceAuthn() && StringUtils.hasText(param("max_age", request))) {
            authnRequest.setForceAuthn(true);
        }
        String acrValues = param("acr_values", request);
        if (StringUtils.hasText(acrValues)) {
            List<ACR> acrList = Arrays.stream(acrValues.split(" ")).map(ACR::new).collect(Collectors.toList());
            parseAcrValues(authnRequest, acrList);
        }
        String requestP = param("request", request);
        String requestUrlP = param("request_uri", request);
        if (StringUtils.hasText(requestP) || StringUtils.hasText(requestUrlP)) {
            OpenIDClient openIDClient = openIDClientRepository.findByClientId(clientId);
            try {
                com.nimbusds.openid.connect.sdk.AuthenticationRequest authRequest =
                        com.nimbusds.openid.connect.sdk.AuthenticationRequest.parse(request);
                authRequest = JWTRequest.parse(authRequest, openIDClient);
                List<ACR> acrValuesObjects = authRequest.getACRValues();
                parseAcrValues(authnRequest, acrValuesObjects);
                Prompt authRequestPrompt = authRequest.getPrompt();
                prompt = AuthorizationEndpoint.validatePrompt(authRequestPrompt);
                if (!authnRequest.isForceAuthn() && authRequest.getMaxAge() > -1) {
                    authnRequest.setForceAuthn(true);
                }
                if (!authnRequest.isForceAuthn() && prompt != null) {
                    authnRequest.setForceAuthn(prompt.contains("login"));
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        String loginHint = param("login_hint", request);
        if (StringUtils.hasText(loginHint)) {
            Scoping scoping = authnRequest.getScoping();
            if (scoping == null) {
                ScopingBuilder scopingBuilder = (ScopingBuilder) registry.getBuilderFactory()
                        .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
                scoping = scopingBuilder.buildObject();
                authnRequest.setScoping(scoping);
            }
            List<String> requesterIds = Stream.of(loginHint.split(",")).map(String::trim).filter(this::isValidURI).collect(Collectors.toList());
            addRequesterIds(requesterIds, scoping);
        }
        return authnRequest;
    }

    private Scoping getScoping(List<String> entityIds) {
        ScopingBuilder scopingBuilder = (ScopingBuilder) registry.getBuilderFactory()
                .getBuilder(Scoping.DEFAULT_ELEMENT_NAME);

        Scoping scoping = scopingBuilder.buildObject();
        addRequesterIds(entityIds, scoping);
        return scoping;
    }

    private void addRequesterIds(List<String> entityIds, Scoping scoping) {
        RequesterIDBuilder requesterIDBuilder = (RequesterIDBuilder) registry.getBuilderFactory()
                .getBuilder(RequesterID.DEFAULT_ELEMENT_NAME);
        List<RequesterID> requesterIDS = entityIds.stream().map(entityId -> {
            RequesterID requesterID = requesterIDBuilder.buildObject();
            requesterID.setRequesterID(entityId);
            return requesterID;
        }).collect(Collectors.toList());

        scoping.setProxyCount(1);
        scoping.getRequesterIDs().addAll(requesterIDS);
    }

    private boolean isValidURI(String uri) {
        try {
            new URI(uri);
            return true;
        } catch (URISyntaxException e) {
            return false;
        }

    }

    private void saveAuthenticationRequestUrl(SavedRequest savedRequest, AuthnRequest authnRequest, ClientID clientID) {
        String id = authnRequest.getID();
        //EB also has a 1 hour validity
        LocalDateTime ldt = LocalDateTime.now().plusHours(1L);
        Date expiresIn = Date.from(ldt.atZone(ZoneId.systemDefault()).toInstant());
        authenticationRequestRepository.insert(
                new oidc.model.AuthenticationRequest(id, expiresIn, clientID != null ? clientID.getValue() : null, savedRequest.getRedirectUrl())
        );
    }

    private void parseAcrValues(AuthnRequest authnRequest, List<ACR> acrValuesObjects) {
        if (!CollectionUtils.isEmpty(acrValuesObjects)) {
            RequestedAuthnContextBuilder requestedAuthnContextBuilder = (RequestedAuthnContextBuilder) registry.getBuilderFactory()
                    .getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
            RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
            requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
            AuthnContextClassRefBuilder authnContextClassRefBuilder = (AuthnContextClassRefBuilder) registry.getBuilderFactory()
                    .getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);

            List<AuthnContextClassRef> authnContextClassRefs = acrValuesObjects.stream().map(acr -> {
                AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
                authnContextClassRef.setAuthnContextClassRef(acr.getValue());
                return authnContextClassRef;
            }).collect(Collectors.toList());
            requestedAuthnContext.getAuthnContextClassRefs().addAll(authnContextClassRefs);
            authnRequest.setRequestedAuthnContext(requestedAuthnContext);
        }
    }

}
