package oidc.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Document(collection = "saml_authentication_requests")
@Getter
@Setter
@AllArgsConstructor
public class SamlAuthenticationRequest {

    @Id
    private String id;

    private String samlRequest;
    private String sigAlg;
    private String signature;
    private String relayState;
    private String authenticationRequestUri;
    private Date expiresAt;

    public SamlAuthenticationRequest() {
        expiresAt = new Date();
    }
}
