package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class JWTRequestURIMismatchException extends BaseException {

    public JWTRequestURIMismatchException(String message) {
        super(message);
    }

    @Override
    public String getErrorCode() {
        return "invalid_request_uri";
    }
}
