package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class RedirectMismatchException extends BaseException {

    public RedirectMismatchException(String message) {
        super(message);
    }

    protected boolean suppressStackTrace() {
        return true;
    }

    @Override
    public String getErrorCode() {
        return "invalid_request_uri";
    }
}
