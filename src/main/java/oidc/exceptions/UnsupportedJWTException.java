package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class UnsupportedJWTException extends RuntimeException {
    public UnsupportedJWTException(String message) {
        super(message);
    }

}
