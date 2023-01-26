package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class UnknownCodeException extends BaseException {

    public UnknownCodeException(String message) {
        super(message);
    }

    protected boolean suppressStackTrace() {
        return true;
    }

    @Override
    public String getErrorCode() {
        return "invalid_code";
    }


}
