package oidc.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TokenValue {

    private String value;
    private String jwtId;

}