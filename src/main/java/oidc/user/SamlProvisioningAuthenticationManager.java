package oidc.user;

import oidc.model.User;
import oidc.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class SamlProvisioningAuthenticationManager implements AuthenticationManager {

    private UserRepository userRepository;

    public SamlProvisioningAuthenticationManager(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(authentication);
            DefaultSamlAuthentication samlAuthentication = (DefaultSamlAuthentication) authentication;
            User user = buildUser(samlAuthentication);
            User existingUser = userRepository.findUserByUnspecifiedNameId(user.getUnspecifiedNameId());
            if (existingUser != null) {
                //TODO compare hashes
                user.setId(existingUser.getId());
                userRepository.save(existingUser);
            } else {
                userRepository.insert(user);
            }
        }
        return authentication;
    }

    private User buildUser(DefaultSamlAuthentication samlAuthentication) {
        User user = new User();
        Assertion assertion = samlAuthentication.getAssertion();
        String unspecifiedNameId = assertion.getSubject().getPrincipal().getValue();
        user.setUnspecifiedNameId(unspecifiedNameId);
        //TODO pick up the authenticating authority from the assertion
        // user.setAuthenticatingAuthority(authenticatingAuthority);
        user.setName(getAttributeValue("urn:mace:dir:attribute-def:cn", assertion));
        user.setPreferredUsername(getAttributeValue("urn:mace:dir:attribute-def:displayName", assertion));
        user.setNickname(getAttributeValue("urn:mace:dir:attribute-def:displayName", assertion));
        user.setGivenName(getAttributeValue("urn:mace:dir:attribute-def:givenName", assertion));
        user.setFamilyName(getAttributeValue("urn:mace:dir:attribute-def:sn", assertion));
        user.setEmail(getAttributeValue("urn:mace:dir:attribute-def:mail", assertion));

        user.setSchacHomeOrganization(getAttributeValue("urn:mace:terena.org:attribute-def:schacHomeOrganization", assertion));
        user.setSchacHomeOrganizationType(getAttributeValue("urn:mace:terena.org:attribute-def:schacHomeOrganizationType", assertion));

        user.setEduPersonAffiliations(getAttributeValues("urn:mace:dir:attribute-def:eduPersonAffiliation", assertion));
        user.setEduPersonScopedAffiliations(getAttributeValues("urn:mace:dir:attribute-def:eduPersonScopedAffiliation", assertion));

        user.setIsMemberOfs(getAttributeValues("urn:mace:dir:attribute-def:isMemberOf", assertion));
        user.setEduPersonEntitlements(getAttributeValues("urn:mace:dir:attribute-def:eduPersonEntitlement", assertion));
        user.setSchacPersonalUniqueCodes(getAttributeValues("urn:schac:attribute-def:schacPersonalUniqueCode", assertion));
        user.setEduPersonPrincipalName(getAttributeValue("urn:mace:dir:attribute-def:eduPersonPrincipalName", assertion));
        user.setUids(getAttributeValues("urn:mace:dir:attribute-def:uid", assertion));
        user.setEduPersonTargetedId(getAttributeValue("urn:mace:dir:attribute-def:eduPersonTargetedID", assertion));

        return user;
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
                return values.stream()
                        .filter(val -> val != null)
                        .map(val -> val.toString())
                        .collect(Collectors.toSet());
            }
        }
        return null;
    }
}
