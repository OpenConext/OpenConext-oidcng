package oidc.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@NoArgsConstructor
@Getter
@Document(collection = "users")
@EqualsAndHashCode
@ToString
public class User implements Serializable {

    @Setter
    @Id
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    private String id;

    private String sub;
    private String unspecifiedNameId;
    private String authenticatingAuthority;
    private String clientId;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private long updatedAt = System.currentTimeMillis() / 1000L;

    private Map<String, Object> attributes = new HashMap<>();
    private List<String> acrClaims = new ArrayList<>();

    public User(String sub, String unspecifiedNameId, String authenticatingAuthority, String clientId,
                Map<String, Object> attributes, List<String> acrClaims) {
        this.sub = sub;
        this.unspecifiedNameId = unspecifiedNameId;
        this.authenticatingAuthority = authenticatingAuthority;
        this.clientId = clientId;
        this.attributes = attributes;
        this.acrClaims = acrClaims;
    }

}
