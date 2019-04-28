package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class ClientAuthenticationNotSupported extends RuntimeException {
    public ClientAuthenticationNotSupported(String message) {
        super(message);
    }
}
