package oidc.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static oidc.manage.ServiceProviderTranslation.translateServiceProviderEntityId;

@Getter
@Document(collection = "clients")
@NoArgsConstructor
public class OpenIDClient {

    @Id
    private String id;
    private String clientId;
    private String name;
    private String secret;
    private List<String> redirectUrls;
    private List<String> scopes;
    private List<String> grants;
    private List<String> allowedResourceServers;
    private boolean resourceServer;
    private boolean publicClient;
    //seconds
    private int accessTokenValidity;
    private int refreshTokenValidity;

    private String discoveryUrl;
    private String signingCertificate;
    private String signingCertificateUrl;

    @SuppressWarnings("unchecked")
    public OpenIDClient(Map<String, Object> root) {
        Map<String, Object> data = (Map<String, Object>) root.get("data");

        this.clientId = translateServiceProviderEntityId(String.class.cast(data.get("entityid")));

        Map<String, Object> metaDataFields = (Map<String, Object>) data.get("metaDataFields");

        this.name = (String) metaDataFields.get("name:en");
        this.secret = (String) metaDataFields.get("secret");
        this.redirectUrls = (List) metaDataFields.get("redirectUrls");
        this.scopes = (List) metaDataFields.getOrDefault("scopes", "oidc");
        this.grants = (List) metaDataFields.getOrDefault("grants", "authorization_code");
        this.allowedResourceServers = ((List<Map<String, String>>) data.getOrDefault("allowedResourceServers", new ArrayList<>()))
                .stream().map(e -> e.get("name")).collect(Collectors.toList());
        this.resourceServer = parseBoolean(metaDataFields.get("isResourceServer"));
        this.publicClient = parseBoolean(metaDataFields.get("isPublicClient"));
        this.accessTokenValidity = (Integer) metaDataFields.getOrDefault("accessTokenValidity", 3600);
        this.refreshTokenValidity = (Integer) metaDataFields.getOrDefault("refreshTokenValidity", 3600);

        this.discoveryUrl = (String) metaDataFields.get("discoveryurl");
        this.signingCertificate = (String) metaDataFields.get("oidc:signingCertificate");
        this.signingCertificateUrl = (String) metaDataFields.get("oidc:signingCertificateUrl");
    }

    @Transient
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
