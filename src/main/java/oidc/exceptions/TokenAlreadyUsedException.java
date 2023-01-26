package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class TokenAlreadyUsedException extends BaseException {
    public TokenAlreadyUsedException(String message) {
        super(message);
    }

    @Override
    public String getErrorCode() {
        return "invalid_grant";
    }

    protected boolean suppressStackTrace() {
        return true;
    }
}
