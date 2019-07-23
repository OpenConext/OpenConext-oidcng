package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class InvalidSignatureException extends BaseException {
    public InvalidSignatureException(String message) {
        super(message);
    }

    @Override
    public String getErrorCode() {
        return "unauthorized_client";
    }


}
