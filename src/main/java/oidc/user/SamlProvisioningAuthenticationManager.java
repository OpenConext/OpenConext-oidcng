package oidc.user;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import oidc.model.User;
import oidc.repository.UserRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationContext;
import org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference;
import org.springframework.security.saml.saml2.authentication.AuthenticationStatement;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class SamlProvisioningAuthenticationManager implements AuthenticationManager {

    private static final Log LOG = LogFactory.getLog(SamlProvisioningAuthenticationManager.class);
    private static final Pattern inResponseToPattern = Pattern.compile("InResponseTo=\"(.+?)\">", Pattern.DOTALL);

    private UserRepository userRepository;
    private List<UserAttribute> userAttributes;

    public SamlProvisioningAuthenticationManager(UserRepository userRepository,
                                                 ObjectMapper objectMapper,
                                                 Resource oidcSamlMapping) throws IOException {
        this.userRepository = userRepository;
        this.userAttributes = objectMapper.readValue(oidcSamlMapping.getInputStream(),
                new TypeReference<List<UserAttribute>>() {
                });
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        DefaultSamlAuthentication samlAuthentication = (DefaultSamlAuthentication) authentication;
        User user = buildUser(samlAuthentication);
        Optional<User> existingUserOptional = userRepository.findOptionalUserBySub(user.getSub());
        if (existingUserOptional.isPresent()) {
            User existingUser = existingUserOptional.get();

            LOG.info("Authenticate with existing user: " + existingUser);

            user.setId(existingUser.getId());
            if (!user.equals(existingUser)) {
                LOG.info("Saving existing user with changed attributes: " + existingUser);
                userRepository.save(existingUser);
            }
        } else {
            LOG.info("Provisioning new user : " + user);
            userRepository.insert(user);
        }
        Matcher matcher = inResponseToPattern.matcher(samlAuthentication.getResponseXml());
        boolean match = matcher.find();
        if (!match) {
            throw new SessionAuthenticationException("Invalid Authn Statement. Missing InResponseTo");
        }
        OidcSamlAuthentication oidcSamlAuthentication =
                new OidcSamlAuthentication(samlAuthentication.getAssertion(), user, matcher.group(1));
        SecurityContextHolder.getContext().setAuthentication(oidcSamlAuthentication);
        return oidcSamlAuthentication;
    }

    private User buildUser(DefaultSamlAuthentication samlAuthentication) {
        Assertion assertion = samlAuthentication.getAssertion();
        String unspecifiedNameId = assertion.getSubject().getPrincipal().getValue();

        List<AuthenticationStatement> authenticationStatements = assertion.getAuthenticationStatements();
        AtomicReference<String> authenticatingAuthority = new AtomicReference<>();
        if (!CollectionUtils.isEmpty(authenticationStatements)) {
            authenticationStatements.stream()
                    .map(as -> as.getAuthenticationContext().getAuthenticatingAuthorities())
                    .flatMap(List::stream)
                    .findAny()
                    .ifPresent(aa -> authenticatingAuthority.set(aa));
        }

        String clientId = samlAuthentication.getRelayState();
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

        List<String> acrClaims = assertion.getAuthenticationStatements().stream()
                .map(authenticationStatement -> authenticationContextClassReference(authenticationStatement.getAuthenticationContext()))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());

        return new User(sub, unspecifiedNameId, authenticatingAuthority.get(), clientId, attributes, acrClaims);
    }

    private void addDerivedAttributes(Map<String, Object> attributes) {
        if (attributes.containsKey("email")) {
            attributes.put("email_verified", true);
        }
    }

    private Optional<String> authenticationContextClassReference(AuthenticationContext authenticationContext) {
        return Optional.ofNullable(authenticationContext)
                .map(AuthenticationContext::getClassReference)
                .map(AuthenticationContextClassReference::getValue);
    }

    private String getAttributeValue(String samlAttributeName, Assertion assertion) {
        Set<String> values = getAttributeValues(samlAttributeName, assertion);
        return !CollectionUtils.isEmpty(values) ? values.iterator().next() : null;
    }

    private Set<String> getAttributeValues(String samlAttributeName, Assertion assertion) {
        Attribute firstAttribute = assertion.getFirstAttribute(samlAttributeName);
        if (firstAttribute != null) {
            List<Object> values = firstAttribute.getValues();
            if (!CollectionUtils.isEmpty(values) && values.size() > 0) {
                return values.stream().filter(Objects::nonNull).map(Object::toString).collect(Collectors.toSet());
            }
        }
        return null;
    }
}
