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
@Document(collection = "access_tokens")
public class AccessToken {

    @Id
    private String id;

    private String innerValue;

    private String value;

    private String sub;

    private String clientId;

    private List<String> scopes;

    private String signingKeyId;

    private Date expiresIn;

    private boolean clientCredentials;

    public AccessToken(String value, String sub, String clientId, List<String> scopes, String signingKeyId, Date expiresIn, boolean clientCredentials) {
        this.innerValue = value;
        this.value = UUID.nameUUIDFromBytes(value.getBytes(Charset.defaultCharset())).toString();
        this.sub = sub;
        this.clientId = clientId;
        this.scopes = scopes;
        this.signingKeyId = signingKeyId;
        this.expiresIn = expiresIn != null ? expiresIn :
                Date.from(LocalDateTime.now().plusSeconds(3600).atZone(ZoneId.systemDefault()).toInstant());
        this.clientCredentials = clientCredentials;
    }

    @Transient
    public boolean isExpired(Clock clock) {
        return clock.instant().isAfter(expiresIn.toInstant());
    }

    public String getSub() {
        return sub;
    }

    public String getClientId() {
        return clientId;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public boolean isClientCredentials() {
        return clientCredentials;
    }

    public Date getExpiresIn() {
        return expiresIn;
    }
}
