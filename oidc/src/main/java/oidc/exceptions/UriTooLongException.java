package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.URI_TOO_LONG)
public class UriTooLongException extends BaseException {

    public UriTooLongException(String message) {
        super(message);
    }

    @Override
    public String getErrorCode() {
        return "uri_too_long";
    }

    @Override
    protected boolean suppressStackTrace() {
        return true;
    }
}
