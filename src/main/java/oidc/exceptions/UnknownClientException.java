package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UnknownClientException extends BaseException {

    public UnknownClientException(String clientID) {
        super(String.format("ClientID %s or secret is not correct", clientID));
    }

    @Override
    public String getErrorCode() {
        return "unauthorized";
    }
}
