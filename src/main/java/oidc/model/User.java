package oidc.model;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.io.Serializable;
import java.util.Map;

@NoArgsConstructor
@Getter
@Document(collection = "users")
@EqualsAndHashCode(exclude = {"id", "updatedAt"})
public class User implements Serializable {

    @Id
    private String id;
    private String sub;
    private String unspecifiedNameId;
    private String authenticatingAuthority;
    private String clientId;
    private long updatedAt = System.currentTimeMillis() / 1000L;
    private Map<String, Object> attributes;

    public User(String sub, String unspecifiedNameId, String authenticatingAuthority, String clientId, Map<String, Object> attributes) {
        this.sub = sub;
        this.unspecifiedNameId = unspecifiedNameId;
        this.authenticatingAuthority = authenticatingAuthority;
        this.clientId = clientId;
        this.attributes = attributes;
    }

    public void setId(String id) {
        this.id = id;
    }
}
