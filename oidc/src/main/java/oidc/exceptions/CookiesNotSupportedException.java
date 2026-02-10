package oidc.exceptions;

public class CookiesNotSupportedException extends BaseException {

    public CookiesNotSupportedException(String message) {
        super(message);
    }

    @Override
    protected boolean suppressStackTrace() {
        return true;
    }


}
