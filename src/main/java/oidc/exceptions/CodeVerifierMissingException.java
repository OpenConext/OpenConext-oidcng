package oidc.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class CodeVerifierMissingException extends BaseException {

    public CodeVerifierMissingException(String message) {
        super(message);
    }

    protected boolean suppressStackTrace() {
        return true;
    }

    @Override
    public String getErrorCode() {
        return "invalid_code_verifier";
    }
}
