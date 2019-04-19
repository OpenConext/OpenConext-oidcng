package oidc.user;

import oidc.model.User;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Map;

public class UserService {

    public User buildUser(Assertion assertion) {
        User user = new User();

//        user.setUnspecifiedNameId(unspecifiedNameId);
//        user.setSub(sub);
//        user.setAuthenticatingAuthority(authenticatingAuthority);
//
//        user.setName(flatten(properties.get("urn:mace:dir:attribute-def:cn")));
//        user.setPreferredUsername(flatten(properties.get("urn:mace:dir:attribute-def:displayName")));
//        user.setNickname(flatten(properties.get("urn:mace:dir:attribute-def:displayName")));
//        user.setGivenName(flatten(properties.get("urn:mace:dir:attribute-def:givenName")));
//        user.setFamilyName(flatten(properties.get("urn:mace:dir:attribute-def:sn")));
//        user.setLocale(flatten(properties.get("urn:mace:dir:attribute-def:preferredLanguage")));
//        user.setEmail(flatten(properties.get("urn:mace:dir:attribute-def:mail")));
//
//        user.setSchacHomeOrganization(flatten(properties.get("urn:mace:terena.org:attribute-def:schacHomeOrganization")));
//        user.setSchacHomeOrganizationType(flatten(properties.get("urn:mace:terena.org:attribute-def:schacHomeOrganizationType")));
//
//        user.setEduPersonAffiliations(set(properties.get("urn:mace:dir:attribute-def:eduPersonAffiliation")));
//        user.setEduPersonScopedAffiliations(set(properties.get("urn:mace:dir:attribute-def:eduPersonScopedAffiliation")));
//
//        user.setIsMemberOfs(set(properties.get("urn:mace:dir:attribute-def:isMemberOf")));
//        user.setEduPersonEntitlements(set(properties.get("urn:mace:dir:attribute-def:eduPersonEntitlement")));
//        user.setSchacPersonalUniqueCodes(set(properties.get("urn:schac:attribute-def:schacPersonalUniqueCode")));
//        user.setEduPersonPrincipalName(flatten(properties.get("urn:mace:dir:attribute-def:eduPersonPrincipalName")));
//        user.setUids(set(properties.get("urn:mace:dir:attribute-def:uid")));
//        user.setEduPersonTargetedId(flatten(properties.get("urn:mace:dir:attribute-def:eduPersonTargetedID")));
//
        return user;
    }

    private String flatten(List<String> values) {
        return CollectionUtils.isEmpty(values) ? null : values.get(0);
    }

}
