package oidc.saml;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import oidc.model.User;
import oidc.repository.UserRepository;
import oidc.user.OidcSamlAuthentication;
import oidc.user.UserAttribute;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.NameID;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.Resource;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

public class ResponseAuthenticationConverter implements Converter<OpenSamlAuthenticationProvider.ResponseToken, OidcSamlAuthentication> {

    private static final Log LOG = LogFactory.getLog(ResponseAuthenticationConverter.class);
    private static final Pattern inResponseToPattern = Pattern.compile("InResponseTo=\"(.+?)\">", Pattern.DOTALL);

    private UserRepository userRepository;
    private List<UserAttribute> userAttributes;
    private ObjectMapper objectMapper;

    public ResponseAuthenticationConverter(UserRepository userRepository,
                                           ObjectMapper objectMapper,
                                           Resource oidcSamlMapping) throws IOException {
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
        this.userAttributes = objectMapper.readValue(oidcSamlMapping.getInputStream(),
                new TypeReference<List<UserAttribute>>() {
                });
    }

    @Override
    public OidcSamlAuthentication convert(OpenSamlAuthenticationProvider.ResponseToken responseToken) {
        Saml2Authentication authentication = OpenSamlAuthenticationProvider
                .createDefaultResponseAuthenticationConverter()
                .convert(responseToken);
        Assertion assertion = responseToken.getResponse().getAssertions().get(0);

        User user = buildUser(assertion);
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
        Matcher matcher = inResponseToPattern.matcher(authentication.getSaml2Response());
        boolean match = matcher.find();
        if (!match) {
            throw new SessionAuthenticationException("Invalid Authn Statement. Missing InResponseTo");
        }
        OidcSamlAuthentication oidcSamlAuthentication =
                new OidcSamlAuthentication(assertion, user, matcher.group(1));
//        SecurityContextHolder.getContext().setAuthentication(oidcSamlAuthentication);
        return oidcSamlAuthentication;

    }

    private User buildUser(Assertion assertion) {
        String unspecifiedNameId = assertion.getSubject().getNameID().getValue();

        List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
        AtomicReference<String> authenticatingAuthority = new AtomicReference<>();
        if (!CollectionUtils.isEmpty(authnStatements)) {
            authnStatements.stream()
                    .map(as -> as.getAuthnContext().getAuthenticatingAuthorities())
                    .flatMap(List::stream)
                    .findAny()
                    .ifPresent(aa -> authenticatingAuthority.set(aa.getURI()));
        }
        //TODO - where to get the  clientID from??
        String clientId = "";//RelayState.from(samlAuthentication.getRelayState(), objectMapper).getClientId();
        //need to prevent NullPointer in HashMap merge
        Map<String, Object> attributes = userAttributes.stream()
                .filter(ua -> !ua.customMapping)
                .map(ua -> new Object[]{ua.oidc, ua.multiValue ? getAttributeValues(ua.saml, assertion) : getAttributeValue(ua.saml, assertion)})
                .filter(oo -> oo[1] != null)
                .collect(Collectors.toMap(oo -> (String) oo[0], oo -> oo[1]));

        this.addDerivedAttributes(attributes);

        String eduPersonTargetedId = getAttributeValue("urn:mace:dir:attribute-def:eduPersonTargetedID", assertion);
        String sub = StringUtils.hasText(eduPersonTargetedId) ? eduPersonTargetedId :
                UUID.nameUUIDFromBytes((unspecifiedNameId + "_" + clientId).getBytes()).toString();
        attributes.put("sub", sub);

        List<String> acrClaims = assertion.getAuthnStatements().stream()
                .map(authenticationStatement -> authenticationContextClassReference(authenticationStatement.getAuthnContext().getAuthnContextClassRef()))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(toList());

        return new User(sub, unspecifiedNameId, authenticatingAuthority.get(), clientId, attributes, acrClaims);
    }

    private void addDerivedAttributes(Map<String, Object> attributes) {
        if (attributes.containsKey("email")) {
            attributes.put("email_verified", true);
        }
    }

    private Optional<String> authenticationContextClassReference(AuthnContextClassRef authnContextClassRef) {
        return Optional.ofNullable(authnContextClassRef)
                .map(AuthnContextClassRef::getAuthnContextClassRef);
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
            return ((XSAny) xmlObject).getTextContent();
        }
        if (xmlObject instanceof XSString) {
            return ((XSString) xmlObject).getValue();
        }
        if (xmlObject instanceof XSInteger) {
            return ((XSInteger) xmlObject).getValue();
        }
        if (xmlObject instanceof XSURI) {
            return ((XSURI) xmlObject).getValue();
        }
        if (xmlObject instanceof XSBoolean) {
            XSBooleanValue xsBooleanValue = ((XSBoolean) xmlObject).getValue();
            return (xsBooleanValue != null) ? xsBooleanValue.getValue() : null;
        }
        if (xmlObject instanceof XSDateTime) {
            DateTime dateTime = ((XSDateTime) xmlObject).getValue();
            return (dateTime != null) ? Instant.ofEpochMilli(dateTime.getMillis()) : null;
        }
        return null;
    }

}
