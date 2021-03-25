package oidc.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;
import java.util.List;

@NoArgsConstructor
@Document(collection = "user_consents")
public class UserConsent {

    @Id
    private String id;

    private String sub;

    private String clientName;

    private List<String> scopes;

    private Date lastAccessed;

    public UserConsent(User user, List<String> scopes, OpenIDClient openIDClient) {
        this.sub = user.getSub();
        this.scopes = scopes;
        this.clientName = openIDClient.getName();
        this.lastAccessed = new Date();
    }

    public List<String> getScopes() {
        return scopes;
    }

    public boolean renewConsentRequired(List<String> newScopes) {
        return !this.scopes.containsAll(newScopes);
    }

    public UserConsent updateScopes(List<String> scopes) {
        this.scopes = scopes;
        this.lastAccessed = new Date();
        return this;
    }
}
