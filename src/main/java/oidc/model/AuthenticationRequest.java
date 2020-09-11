package oidc.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Document(collection = "authentication_requests")
@Getter
@NoArgsConstructor
public class AuthenticationRequest {

    @Id
    private String id;

    private Date expiresIn;

    private String originalRequestUrl;

    private String userId;

    public AuthenticationRequest(String id, Date expiresIn, String originalRequestUrl) {
        this.id = id;
        this.expiresIn = expiresIn;
        this.originalRequestUrl = originalRequestUrl;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
