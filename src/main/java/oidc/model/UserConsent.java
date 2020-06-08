package oidc.model;

import lombok.NoArgsConstructor;
import oidc.crypto.KeyGenerator;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.mapping.Document;

import java.nio.charset.Charset;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@NoArgsConstructor
@Document(collection = "user_consents")
public class UserConsent {

    @Id
    private String id;

    private String sub;

    private String clientName;

    private List<String> scopes;

    private int hash;

    private Date lastAccessed;

    public UserConsent(User user, List<String> scopes, OpenIDClient openIDClient) {
        this.sub = user.getSub();
        this.scopes = scopes;
        this.clientName = openIDClient.getName();
        this.hash = user.hashCode();
        this.lastAccessed = new Date();
    }

    public int getHash() {
        return hash;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public UserConsent updateHash(User user, List<String> scopes) {
        this.hash = user.hashCode();
        this.scopes = scopes;
        this.lastAccessed = new Date();
        return this;
    }

    public boolean renewConsentRequired(User user, List<String> newScopes) {
        return hash != user.hashCode() || !this.scopes.containsAll(newScopes);
    }

}
