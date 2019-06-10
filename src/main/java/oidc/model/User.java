package oidc.model;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

@NoArgsConstructor
@Getter
@Document(collection = "users")
@EqualsAndHashCode
public class User implements Serializable {

    @Id
    @EqualsAndHashCode.Exclude
    private String id;
    private String sub;
    private String unspecifiedNameId;
    private String authenticatingAuthority;
    private String clientId;
    @EqualsAndHashCode.Exclude
    private long updatedAt = System.currentTimeMillis() / 1000L;
    private Map<String, Object> attributes;
    private List<String> acrClaims;

    public User(String sub, String unspecifiedNameId, String authenticatingAuthority, String clientId,
                Map<String, Object> attributes, List<String> acrClaims) {
        this.sub = sub;
        this.unspecifiedNameId = unspecifiedNameId;
        this.authenticatingAuthority = authenticatingAuthority;
        this.clientId = clientId;
        this.attributes = attributes;
        this.acrClaims = acrClaims;
    }

    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String toString() {
        return "User{" +
                "sub='" + sub + '\'' +
                ", unspecifiedNameId='" + unspecifiedNameId + '\'' +
                ", clientId='" + clientId + '\'' +
                '}';
    }
}
