package oidc.model;


import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Map;

@Getter
@Document(collection = "identity_providers")
@NoArgsConstructor
public class IdentityProvider {

    @Id
    private String id;

    private String entityId;
    private String name;
    private String nameNl;

    @SuppressWarnings("unchecked")
    public IdentityProvider(Map<String, Object> root) {
        Map<String, Object> data = (Map<String, Object>) root.get("data");

        this.entityId = (String) data.get("entityid");

        Map<String, Object> metaDataFields = (Map<String, Object>) data.get("metaDataFields");

        this.name = (String) metaDataFields.get("name:en");
        this.nameNl = (String) metaDataFields.get("name:nl");
    }
}