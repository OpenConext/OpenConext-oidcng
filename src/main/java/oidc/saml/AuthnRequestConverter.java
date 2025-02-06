package oidc.saml;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import lombok.SneakyThrows;
import oidc.endpoints.AuthorizationEndpoint;
import oidc.exceptions.CookiesNotSupportedException;
import oidc.exceptions.InvalidGrantException;
import oidc.exceptions.JWTRequestURIMismatchException;
import oidc.exceptions.UnknownClientException;
import oidc.log.MDCContext;
import oidc.manage.ServiceProviderTranslation;
import oidc.model.OpenIDClient;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.secure.JWTRequest;
import oidc.web.URLCoding;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding.POST;


public class AuthnRequestConverter implements
        Converter<Saml2AuthenticationToken, AuthnRequest>, URLCoding {

    public final static String REDIRECT_URI_VALID = "REDIRECT_URI_VALID";

    private static final Log LOG = LogFactory.getLog(AuthnRequestConverter.class);

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
    public AuthnRequest convert(Saml2AuthenticationToken ctx) {
        CustomSaml2AuthenticationRequestContext context = (CustomSaml2AuthenticationRequestContext) ctx;
        HttpServletRequest request = context.getRequest();

        HttpSession session = request.getSession(false);
        if (session == null) {
            LOG.warn("There is no session in the HttpServletRequest. CookiesNotSupportedException will be thrown");
        } else {
            Enumeration<String> attributeNames = session.getAttributeNames();
            List<String> list = Collections.list(attributeNames);
            if (!list.contains("SPRING_SECURITY_SAVED_REQUEST")) {
                LOG.warn("There is a session in the HttpServletRequest with ID " + session.getId() + " which does not contain a saved request. Attribute names are: " + list);
            }
        }

        SavedRequest savedRequest = requestCache.getRequest(request, null);

        if (savedRequest == null) {
            throw new CookiesNotSupportedException();
        }

        Map<String, String[]> parameterMap = savedRequest.getParameterMap();
        Map<String, List<String>> parameters = parameterMap.keySet().stream()
                .collect(Collectors.toMap(key -> key, key -> Arrays.asList(parameterMap.get(key))));
        List<String> clientIds = parameters.get("client_id");
        String clientId = CollectionUtils.isEmpty(clientIds) ? null : clientIds.get(0);
        if (!StringUtils.hasText(clientId)) {
            throw new UnknownClientException(String.format("client_id parameter missing in parameters: %s", parameters));
        }
        OpenIDClient openIDClient = openIDClientRepository.findOptionalByClientId(clientId)
                .orElseThrow(() -> new UnknownClientException(clientId));

        //If this a device code flow, we don't validate redirect URI's
        List<String> userCode = parameters.get("user_code");
        if (!CollectionUtils.isEmpty(userCode)) {
            List<String> grants = openIDClient.getGrants();
            if (!grants.contains(GrantType.DEVICE_CODE.getValue())) {
                throw new InvalidGrantException(String.format("Grant types %s for client %s does not allow for device code flow",
                        grants, openIDClient.getClientId()));
            }
        } else {
            List<String> redirectUris = parameters.get("redirect_uri");
            URI redirectURI = CollectionUtils.isEmpty(redirectUris) ? null : new URI(redirectUris.get(0));

            AuthorizationEndpoint.validateRedirectionURI(redirectURI, openIDClient);
            request.setAttribute(REDIRECT_URI_VALID, true);

            AuthorizationRequest authorizationRequest = AuthorizationRequest.parse(parameters);

            validateAuthorizationRequest(authorizationRequest, openIDClient);
        }

        RelyingPartyRegistration relyingParty = context.getRelyingPartyRegistration();
        AuthnRequestBuilder authnRequestBuilder = (AuthnRequestBuilder) registry.getBuilderFactory()
                .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest authnRequest = authnRequestBuilder.buildObject();
        authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
        authnRequest.setIssueInstant(Instant.now());

        authnRequest.setProtocolBinding(POST.getUrn());

        IssuerBuilder issuerBuilder = (IssuerBuilder) registry.getBuilderFactory()
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(relyingParty.getEntityId());
        authnRequest.setIssuer(issuer);
        // @TODO: correct retrieval of data?
        authnRequest.setDestination(context.getRelyingPartyRegistration().getAssertingPartyDetails().getSingleSignOnServiceLocation());
        authnRequest.setAssertionConsumerServiceURL(context.getRelyingPartyRegistration().getAssertionConsumerServiceLocation());

        saveAuthenticationRequestUrl(savedRequest, authnRequest, new ClientID(clientId));
        return enhanceAuthenticationRequest(authnRequest, parameters);
    }

    public void enrichAuthnRequest(AuthnRequest authnRequest, RelyingPartyRegistration relyingParty,
                                   HttpServletRequest request)
            throws ParseException, URISyntaxException, UnsupportedEncodingException {

        HttpSession session = request.getSession(false);
        if (session == null) {
            LOG.warn("There is no session in the HttpServletRequest. CookiesNotSupportedException will be thrown");
        } else {
            Enumeration<String> attributeNames = session.getAttributeNames();
            List<String> list = Collections.list(attributeNames);
            if (!list.contains("SPRING_SECURITY_SAVED_REQUEST")) {
                LOG.warn("There is a session in the HttpServletRequest with ID " + session.getId() + " which does not contain a saved request. Attribute names are: " + list);
            }
        }

        SavedRequest savedRequest = requestCache.getRequest(request, null);

        if (savedRequest == null) {
            throw new CookiesNotSupportedException();
        }

        Map<String, String[]> parameterMap = savedRequest.getParameterMap();
        Map<String, List<String>> parameters = parameterMap.keySet().stream()
                .collect(Collectors.toMap(key -> key, key -> Arrays.asList(parameterMap.get(key))));
        List<String> clientIds = parameters.get("client_id");
        String clientId = CollectionUtils.isEmpty(clientIds) ? null : clientIds.get(0);
        if (!StringUtils.hasText(clientId)) {
            throw new UnknownClientException(String.format("client_id parameter missing in parameters: %s", parameters));
        }
        OpenIDClient openIDClient = openIDClientRepository.findOptionalByClientId(clientId)
                .orElseThrow(() -> new UnknownClientException(clientId));

        //If this a device code flow, we don't validate redirect URI's
        List<String> userCode = parameters.get("user_code");
        if (!CollectionUtils.isEmpty(userCode)) {
            List<String> grants = openIDClient.getGrants();
            if (!grants.contains(GrantType.DEVICE_CODE.getValue())) {
                throw new InvalidGrantException(String.format("Grant types %s for client %s does not allow for device code flow",
                        grants, openIDClient.getClientId()));
            }
        } else {
            List<String> redirectUris = parameters.get("redirect_uri");
            URI redirectURI = CollectionUtils.isEmpty(redirectUris) ? null : new URI(redirectUris.get(0));

            AuthorizationEndpoint.validateRedirectionURI(redirectURI, openIDClient);
            request.setAttribute(REDIRECT_URI_VALID, true);

            AuthorizationRequest authorizationRequest = AuthorizationRequest.parse(parameters);

            validateAuthorizationRequest(authorizationRequest, openIDClient);
        }

        authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
        authnRequest.setIssueInstant(Instant.now());

        authnRequest.setProtocolBinding(POST.getUrn());

        IssuerBuilder issuerBuilder = (IssuerBuilder) registry.getBuilderFactory()
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(relyingParty.getEntityId());
        authnRequest.setIssuer(issuer);
        // @TODO: correct retrieval of data?
        authnRequest.setDestination(relyingParty.getAssertingPartyDetails().getSingleSignOnServiceLocation());
        authnRequest.setAssertionConsumerServiceURL(relyingParty.getAssertionConsumerServiceLocation());

        enhanceAuthenticationRequest(authnRequest, parameters);
    }

    @SneakyThrows
    private void validateAuthorizationRequest(AuthorizationRequest authorizationRequest, OpenIDClient openIDClient) {
        ClientID clientID = authorizationRequest.getClientID();
        MDCContext.mdcContext("action", "Authorization", "clientId", clientID.getValue());

        AuthorizationEndpoint.validateScopes(openIDClientRepository, authorizationRequest.getScope(), openIDClient);
        AuthorizationEndpoint.validateGrantType(authorizationRequest, openIDClient);
    }

    private String param(String name, Map<String, List<String>> request) {
        List<String> values = request.get(name);
        return CollectionUtils.isEmpty(values) ? null : values.get(0);
    }

    private AuthnRequest enhanceAuthenticationRequest(AuthnRequest authnRequest,
                                                      Map<String, List<String>> request) throws ParseException, UnsupportedEncodingException {
        String clientId = param("client_id", request);

        String entityId = ServiceProviderTranslation.translateClientId(clientId);
        authnRequest.setScoping(getScoping(entityId));
        String prompt = AuthorizationEndpoint.validatePrompt(request);

        authnRequest.setForceAuthn(prompt != null && prompt.contains("login"));

        /*
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
            OpenIDClient openIDClient = openIDClientRepository.findOptionalByClientId(clientId)
                    .orElseThrow(() -> new UnknownClientException(clientId));
            if (StringUtils.hasText(requestUrlP) && !requestUrlP.equalsIgnoreCase(openIDClient.getJwtRequestUri())) {
                throw new JWTRequestURIMismatchException(
                        String.format("JWT request_uri mismatch for RP %s. Requested %s, configured %s",
                                openIDClient.getClientId(), requestUrlP, openIDClient.getJwtRequestUri()));
            }
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
            } catch (CertificateException | JOSEException | IOException | BadJOSEException |
                     java.text.ParseException | URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }
        String loginHint = param("login_hint", request);
        if (StringUtils.hasText(loginHint)) {
            loginHint = URLDecoder.decode(loginHint, Charset.defaultCharset().name());
            IDPList idpList = addIdpEntries(loginHint);
            Scoping scoping = authnRequest.getScoping();
            scoping.setIDPList(idpList);
        }
        return authnRequest;
    }

    private IDPList addIdpEntries(String loginHint) {
        IDPEntryBuilder idpEntryBuilder = (IDPEntryBuilder) registry.getBuilderFactory().getBuilder(IDPEntry.DEFAULT_ELEMENT_NAME);
        List<IDPEntry> idpEntries = Stream.of(loginHint.split(","))
                .map(String::trim)
                .filter(this::isValidURI)
                .map(s -> {
                    IDPEntry idpEntry = idpEntryBuilder.buildObject();
                    idpEntry.setProviderID(s);
                    return idpEntry;
                })
                .collect(Collectors.toList());
        IDPList idpList = ((IDPListBuilder) registry.getBuilderFactory().getBuilder(IDPList.DEFAULT_ELEMENT_NAME)).buildObject();
        idpList.getIDPEntrys().addAll(idpEntries);
        return idpList;
    }

    private Scoping getScoping(String entityId) {
        ScopingBuilder scopingBuilder = (ScopingBuilder) registry.getBuilderFactory()
                .getBuilder(Scoping.DEFAULT_ELEMENT_NAME);

        Scoping scoping = scopingBuilder.buildObject();
        addRequesterIds(entityId, scoping);
        return scoping;
    }

    private void addRequesterIds(String entityId, Scoping scoping) {
        RequesterIDBuilder requesterIDBuilder = (RequesterIDBuilder) registry.getBuilderFactory()
                .getBuilder(RequesterID.DEFAULT_ELEMENT_NAME);
            RequesterID requesterID = requesterIDBuilder.buildObject();
            requesterID.setURI(entityId);

        scoping.setProxyCount(1);
        scoping.getRequesterIDs().add(requesterID);
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
        //EB also has a 1-hour validity
        LocalDateTime ldt = LocalDateTime.now().plusHours(1L);
        Date expiresIn = Date.from(ldt.atZone(ZoneId.systemDefault()).toInstant());

        LOG.debug("Saving AuthenticationRequest with redirectURL: " + savedRequest.getRedirectUrl());

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
                authnContextClassRef.setURI(acr.getValue());
                return authnContextClassRef;
            }).collect(Collectors.toList());
            requestedAuthnContext.getAuthnContextClassRefs().addAll(authnContextClassRefs);
            authnRequest.setRequestedAuthnContext(requestedAuthnContext);
        }
    }

}
