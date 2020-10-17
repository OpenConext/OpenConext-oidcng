package oidc.exceptions;

public abstract class BaseException extends RuntimeException {

    public BaseException(String errorMsg) {
        super(errorMsg);
    }

    public abstract String getErrorCode();

}
