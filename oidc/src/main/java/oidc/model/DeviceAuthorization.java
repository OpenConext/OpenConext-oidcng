package oidc.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.List;

@Document(collection = "device_authorizations")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class DeviceAuthorization {

    @Id
    private String id;

    private String clientId;

    private String deviceCode;

    private String userCode;

    private List<String> scopes;

    private String state;

    //The following parameters are not mentioned in the spec, but a device may add them to dictate the way the user authenticates
    private String prompt;
    private String acrValues;
    private String loginHint;

    @Setter
    private DeviceAuthorizationStatus status;

    @Setter
    private Instant lastLookup;

    @Setter
    private String userSub;

    private Instant expiresAt;

}
