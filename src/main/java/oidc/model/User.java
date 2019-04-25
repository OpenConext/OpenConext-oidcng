package oidc.model;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Document(collection = "users")
@EqualsAndHashCode(exclude = {"id", "authenticatingAuthority"})
@ToString(exclude = {"id"})
public class User implements Serializable {

    @Id
    private String id;
    private String sub;
    private String preferredUsername;
    private String name;
    private String givenName;
    private String familyName;
    private String middleName;
    private String nickname;
    private String email;
    private String phoneNumber;

    private String schacHomeOrganization;
    private String unspecifiedNameId;
    private String authenticatingAuthority;
    private String schacHomeOrganizationType;
    private String eduPersonPrincipalName;
    private String eduPersonTargetedId;
    private String clientId;

    private Set<String> eduPersonAffiliations;
    private Set<String> eduPersonScopedAffiliations;
    private Set<String> isMemberOfs;
    private Set<String> eduPersonEntitlements;
    private Set<String> schacPersonalUniqueCodes;
    private Set<String> uids;
}
