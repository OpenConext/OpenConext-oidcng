package oidc.saml;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import oidc.model.AuthenticationRequest;
import oidc.model.User;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.UserRepository;
import oidc.user.OidcSamlAuthentication;
import oidc.user.UserAttribute;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.*;
import org.opensaml.saml.saml2.core.*;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.Resource;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

public class ResponseAuthenticationConverter implements Converter<OpenSaml4AuthenticationProvider.ResponseToken, OidcSamlAuthentication> {

    private static final Log LOG = LogFactory.getLog(ResponseAuthenticationConverter.class);
    private static final Pattern inResponseToPattern = Pattern.compile("InResponseTo=\"(.+?)\"", Pattern.DOTALL);
    private final Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> defaultResponseAuthenticationConverter;

    private final UserRepository userRepository;
    private final List<UserAttribute> userAttributes;
    private final AuthenticationRequestRepository authenticationRequestRepository;

    public ResponseAuthenticationConverter(UserRepository userRepository,
                                           AuthenticationRequestRepository authenticationRequestRepository,
                                           ObjectMapper objectMapper,
                                           Resource oidcSamlMapping) throws IOException {
        this.userRepository = userRepository;
        this.authenticationRequestRepository = authenticationRequestRepository;
        this.userAttributes = objectMapper.readValue(oidcSamlMapping.getInputStream(),new TypeReference<>() {});
        this.defaultResponseAuthenticationConverter = OpenSaml4AuthenticationProvider
                .createDefaultResponseAuthenticationConverter();
    }

    @Override
    public OidcSamlAuthentication convert(OpenSaml4AuthenticationProvider.ResponseToken responseToken) {
        Saml2Authentication authentication = defaultResponseAuthenticationConverter
                .convert(responseToken);
        Assertion assertion = responseToken.getResponse().getAssertions().get(0);
        Matcher matcher = inResponseToPattern.matcher(authentication.getSaml2Response());
        boolean match = matcher.find();
        if (!match) {
            throw new SessionAuthenticationException("Invalid Authn Statement. Missing InResponseTo");
        }
        String authenticationRequestID = matcher.group(1);

        User user = buildUser(assertion, authenticationRequestID);
        Optional<User> existingUserOptional = userRepository.findOptionalUserBySub(user.getSub());
        if (existingUserOptional.isPresent()) {
            User existingUser = existingUserOptional.get();

            LOG.debug("Authenticate with existing user: " + existingUser);

            user.setId(existingUser.getId());
            if (!user.equals(existingUser)) {
                LOG.debug("Saving existing user with changed attributes: " + existingUser);
                userRepository.save(existingUser);
            }
        } else {
            LOG.debug("Provisioning new user : " + user);
            userRepository.insert(user);
        }
        OidcSamlAuthentication oidcSamlAuthentication =
                new OidcSamlAuthentication(assertion, user, authenticationRequestID);

        return oidcSamlAuthentication;

    }

    private User buildUser(Assertion assertion, String authenticationRequestID) {
        List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
        AtomicReference<String> authenticatingAuthority = new AtomicReference<>();
        if (!CollectionUtils.isEmpty(authnStatements)) {
            authnStatements.stream()
                    .map(as -> as.getAuthnContext().getAuthenticatingAuthorities())
                    .flatMap(List::stream)
                    .findAny()
                    .ifPresent(aa -> authenticatingAuthority.set(aa.getURI()));
        }
        //need to prevent NullPointer in HashMap merge
        Map<String, Object> attributes = userAttributes.stream()
                .filter(ua -> !ua.customMapping)
                .map(ua -> new Object[]{ua.oidc, ua.multiValue ? getAttributeValues(ua.saml, assertion) : getAttributeValue(ua.saml, assertion)})
                .filter(oo -> oo[1] != null)
                .collect(Collectors.toMap(oo -> (String) oo[0], oo -> oo[1]));

        this.addDerivedAttributes(attributes);

        AuthenticationRequest authenticationRequest = authenticationRequestRepository.findById(authenticationRequestID).orElseThrow(
                () -> new IllegalArgumentException("No Authentication Request found for ID: " + authenticationRequestID));
        String clientId = authenticationRequest.getClientId();

        String nameId = assertion.getSubject().getNameID().getValue();
        String eduPersonTargetedId = getAttributeValue("urn:mace:dir:attribute-def:eduPersonTargetedID", assertion);
        String collabPersonId = getAttributeValue("urn:mace:surf.nl:attribute-def:internal-collabPersonId", assertion);
        String sub;
        if (StringUtils.hasText(collabPersonId)) {
            sub = nameId;
            nameId = collabPersonId;
        } else if (StringUtils.hasText(eduPersonTargetedId)) {
            sub = eduPersonTargetedId;
        } else {
            sub = UUID.nameUUIDFromBytes((nameId + "_" + clientId).getBytes()).toString();
        }
        attributes.put("sub", sub);

        List<String> acrClaims = assertion.getAuthnStatements().stream()
                .map(authenticationStatement -> authenticationContextClassReference(authenticationStatement.getAuthnContext().getAuthnContextClassRef()))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(toList());

        return new User(sub, nameId, authenticatingAuthority.get(), clientId, attributes, acrClaims);
    }

    private void addDerivedAttributes(Map<String, Object> attributes) {
        if (attributes.containsKey("email")) {
            attributes.put("email_verified", true);
        }
    }

    private Optional<String> authenticationContextClassReference(AuthnContextClassRef authnContextClassRef) {
        return Optional.ofNullable(authnContextClassRef)
                .map(AuthnContextClassRef::getURI);
    }

    private String getAttributeValue(String samlAttributeName, Assertion assertion) {
        List<String> values = getAttributeValues(samlAttributeName, assertion);
        return !CollectionUtils.isEmpty(values) ? values.get(0) : null;
    }

    private List<String> getAttributeValues(String samlAttributeName, Assertion assertion) {
        Optional<List<String>> values = assertion.getAttributeStatements()
                .stream()
                .map(AttributeStatement::getAttributes).flatMap(Collection::stream)
                .filter(attribute -> attribute.getName().equals(samlAttributeName))
                .findAny()
                .map(attribute -> attribute.getAttributeValues().stream().map(xmlObject -> getXmlObjectValue(xmlObject))
                        .filter(Objects::nonNull)
                        .map(val -> val.toString())
                        .collect(toList()));
        return values.orElse(null);
    }

    private Object getXmlObjectValue(XMLObject xmlObject) {
        if (xmlObject instanceof XSAny) {
            XSAny xsAny = (XSAny) xmlObject;
            String textContent = xsAny.getTextContent();
            if (StringUtils.hasText(textContent)) {
                return textContent;
            }
            List<XMLObject> unknownXMLObjects = xsAny.getUnknownXMLObjects();
            if (!CollectionUtils.isEmpty(unknownXMLObjects)) {
                XMLObject unknownXMLObject = unknownXMLObjects.get(0);
                if (unknownXMLObject instanceof NameID) {
                    NameID nameID = (NameID) unknownXMLObject;
                    return nameID.getValue();
                }
            }
        }
        if (xmlObject instanceof XSString) {
            return ((XSString) xmlObject).getValue();
        }
        if (xmlObject instanceof XSInteger) {
            return ((XSInteger) xmlObject).getValue();
        }
        if (xmlObject instanceof XSURI) {
            return ((XSURI) xmlObject).getURI();
        }
        if (xmlObject instanceof XSBoolean) {
            XSBooleanValue xsBooleanValue = ((XSBoolean) xmlObject).getValue();
            return (xsBooleanValue != null) ? xsBooleanValue.getValue() : null;
        }
        if (xmlObject instanceof XSDateTime) {
            return ((XSDateTime) xmlObject).getValue();
        }
        return null;
    }

}
