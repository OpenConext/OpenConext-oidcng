package oidc.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

import static oidc.manage.ServiceProviderTranslation.translateServiceProviderEntityId;

@Getter
@Setter
public class OpenIDClient {

    private String clientId;
    private String secret;
    private List<String> redirectUrls;
    private List<String> scopes;
    private List<String> grants;
    private boolean resourceServer;

    public OpenIDClient(Map<String, Object> root) {
        Map<String, Object> data = (Map<String, Object>) root.get("data");

        this.clientId = translateServiceProviderEntityId(String.class.cast(data.get("entityid")));

        Map<String, Object> oidc = (Map<String, Object>) data.get("oidc");

        this.secret = String.class.cast(oidc.get("secret"));
        this.redirectUrls = List.class.cast(oidc.get("redirectUrls"));
        this.scopes = List.class.cast(oidc.get("scopes"));
        this.grants = List.class.cast(oidc.get("grants"));
        this.resourceServer = Boolean.class.cast(oidc.get("resourceServer"));
    }

}
