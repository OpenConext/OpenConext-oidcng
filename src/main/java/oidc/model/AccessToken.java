package oidc.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@NoArgsConstructor
@Getter
@Setter
@Document(collection = "access_tokens")
public class AccessToken {

    @Id
    private String id;

    private String value;

    private String sub;

    private String clientId;

    private List<String> scopes;

    public AccessToken(String value, String sub, String clientId, List<String> scopes) {
        this.value = value;
        this.sub = sub;
        this.clientId = clientId;
        this.scopes = scopes;
    }
}
