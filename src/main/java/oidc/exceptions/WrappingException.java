package oidc.exceptions;

import lombok.Getter;

public class WrappingException extends BaseException {

    @Getter
    private final Exception originalException;

    public WrappingException(String errorMsg, Exception originalException) {
        super(errorMsg);
        this.originalException = originalException;
    }
}
