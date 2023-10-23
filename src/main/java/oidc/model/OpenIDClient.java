package oidc.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static oidc.manage.ServiceProviderTranslation.translateServiceProviderEntityId;
import static oidc.model.EntityType.OAUTH_RS;

@Getter
@Document(collection = "clients")
@NoArgsConstructor
public class OpenIDClient {

    @Transient
    private static final List<String> nameIdFormats = Arrays.asList("NameIDFormat", "NameIDFormats:0", "NameIDFormats:1", "NameIDFormats:2");

    @Id
    private String id;
    private String clientId;
    private String institutionGuid;
    private String organisationName;
    private String organisationNameNl;
    private String name;
    private String nameNl;
    private String description;
    private String descriptionNl;
    private String secret;
    private String clientSecretJWT;
    private String logoUrl;
    private List<String> redirectUrls;
    private List<Scope> scopes;
    private List<String> grants;
    private List<String> allowedResourceServers;
    private String jwtRequestUri;
    private boolean resourceServer;
    private boolean publicClient;
    //seconds
    private int accessTokenValidity;
    private int refreshTokenValidity;

    private String discoveryUrl;
    private String signingCertificate;
    private String signingCertificateUrl;

    private boolean includeUnspecifiedNameID;
    private boolean consentRequired;
    private boolean claimsInIdToken;

    public OpenIDClient(String clientId, List<String> redirectUrls, List<Scope> scopes, List<String> grants) {
        this.clientId = clientId;
        this.redirectUrls = redirectUrls;
        this.scopes = scopes;
        this.grants = grants;
    }

    @SuppressWarnings("unchecked")
    public OpenIDClient(Map<String, Object> root) {
        Map<String, Object> data = (Map<String, Object>) root.get("data");

        this.clientId = translateServiceProviderEntityId(String.class.cast(data.get("entityid")));

        Map<String, Object> metaDataFields = (Map<String, Object>) data.get("metaDataFields");

        this.institutionGuid = (String) metaDataFields.get("coin:institution_guid");
        this.organisationName = (String) metaDataFields.get("OrganizationName:en");
        this.organisationNameNl = (String) metaDataFields.get("OrganizationName:nl");
        this.name = (String) metaDataFields.get("name:en");
        this.nameNl = (String) metaDataFields.get("name:nl");
        this.description = (String) metaDataFields.get("description:en");
        this.descriptionNl = (String) metaDataFields.get("description:nl");
        this.secret = (String) metaDataFields.get("secret");
        this.clientSecretJWT = (String) metaDataFields.get("clientSecretJWT");
        this.logoUrl = (String) metaDataFields.get("logo:0:url");
        this.redirectUrls = (List) metaDataFields.get("redirectUrls");
        this.jwtRequestUri = (String) metaDataFields.get("oidc:jwtRequestUri");

        this.grants = (List) metaDataFields.getOrDefault("grants", Collections.singletonList("authorization_code"));
        this.allowedResourceServers = ((List<Map<String, String>>) data.getOrDefault("allowedResourceServers", new ArrayList<>()))
                .stream().map(e -> e.get("name")).collect(Collectors.toList());
        this.resourceServer = parseBoolean(metaDataFields.get("isResourceServer")) || root.get("type").equals(OAUTH_RS.getType());
        this.scopes = (List<Scope>) ((List) metaDataFields.getOrDefault("scopes", new ArrayList<>())).stream()
                .map(val -> val instanceof String ? new Scope((String) val) : new Scope((Map<String, Object>) val))
                .collect(Collectors.toList());
        this.publicClient = parseBoolean(metaDataFields.get("isPublicClient"));
        this.accessTokenValidity = (Integer) metaDataFields.getOrDefault("accessTokenValidity", 3600);
        this.refreshTokenValidity = (Integer) metaDataFields.getOrDefault("refreshTokenValidity", 3600);

        this.discoveryUrl = (String) metaDataFields.get("discoveryurl");
        this.signingCertificate = (String) metaDataFields.get("oidc:signingCertificate");
        this.signingCertificateUrl = (String) metaDataFields.get("oidc:signingCertificateUrl");
        this.consentRequired = parseBoolean(metaDataFields.get("oidc:consentRequired"));
        this.claimsInIdToken = parseBoolean(metaDataFields.get("oidc:claims_in_id_token"));

        this.includeUnspecifiedNameID = nameIdFormats.stream()
                .filter(metaDataFields::containsKey)
                .anyMatch(id -> metaDataFields.get(id).equals("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"));
    }

    @Transient
    public boolean certificateSpecified() {
        return StringUtils.hasText(signingCertificate) || StringUtils.hasText(signingCertificateUrl)
                || StringUtils.hasText(discoveryUrl);
    }

    @Transient
    //Backward compatibility with older versions of Manage where all metadata values where Strings
    private boolean parseBoolean(Object val) {
        if (val instanceof Boolean) {
            return (boolean) val;
        }
        if (val instanceof String) {
            return "1".equals(val);
        }
        return false;
    }

}
