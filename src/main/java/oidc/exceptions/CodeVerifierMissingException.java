package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class CodeVerifierMissingException extends RuntimeException {
    public CodeVerifierMissingException(String message) {
        super(message);
    }
}
