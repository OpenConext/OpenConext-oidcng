package oidc.model;

import lombok.NoArgsConstructor;
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

    private int hash;

    private Date lastAccessed;

    public UserConsent(User user) {
        this.sub = user.getSub();
        this.hash = user.hashCode();
        this.lastAccessed = new Date();
    }

    public int getHash() {
        return hash;
    }

    public UserConsent updateHash(User user) {
        this.hash = user.hashCode();
        this.lastAccessed = new Date();
        return this;
    }
}
