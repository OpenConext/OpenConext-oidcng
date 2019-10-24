package oidc.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class EncryptedTokenValue {

    private String value;
    private String keyId;



}
