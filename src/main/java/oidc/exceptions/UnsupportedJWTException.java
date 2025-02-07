package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class UnsupportedJWTException extends BaseException {

    public UnsupportedJWTException(String message) {
        super(message);
    }

    @Override
    public String getErrorCode() {
        return "request_not_supported";
    }


}
