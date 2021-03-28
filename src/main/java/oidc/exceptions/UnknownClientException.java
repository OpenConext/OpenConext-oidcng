package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UnknownClientException extends BaseException {

    public UnknownClientException() {
        super("ClientID or secret is not correct ");
    }

    @Override
    public String getErrorCode() {
        return "unauthorized";
    }
}
