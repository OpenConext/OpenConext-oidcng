package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class InvalidScopeException extends BaseException {
    public InvalidScopeException(String message) {
        super(message);
    }

    @Override
    public String getErrorCode() {
        return "invalid_scope";
    }
}
