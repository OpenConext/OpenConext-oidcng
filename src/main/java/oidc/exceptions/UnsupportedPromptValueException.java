package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class UnsupportedPromptValueException extends BaseException {

    private final String errorCode;

    public UnsupportedPromptValueException(String errorCode, String msg) {
        super(msg);
        this.errorCode = errorCode;
    }

    protected boolean suppressStackTrace() {
        return true;
    }

    @Override
    public String getErrorCode() {
        return this.errorCode;
    }


}
