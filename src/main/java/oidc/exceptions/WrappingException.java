package oidc.exceptions;

public class WrappingException extends BaseException {

    public WrappingException(String errorMsg) {
        super(errorMsg);
    }

    @Override
    public String getErrorCode() {
        return "invalid_request";
    }
}
