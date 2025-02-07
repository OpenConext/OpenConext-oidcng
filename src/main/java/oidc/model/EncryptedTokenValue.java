package oidc.model;

import lombok.Getter;

@Getter
public class EncryptedTokenValue {

    private String value;
    private String keyId;
    private String jwtId;

    public EncryptedTokenValue(TokenValue tokenValue, String keyId) {
        this.keyId = keyId;
        this.value = tokenValue.getValue();
        this.jwtId = tokenValue.getJwtId();
    }

}
