package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class JWTAuthorizationGrantsException extends BaseException {
    public JWTAuthorizationGrantsException(String message) {
        super(message);
    }

    @Override
    public String getErrorCode() {
        return "invalid_grant";
    }
}
