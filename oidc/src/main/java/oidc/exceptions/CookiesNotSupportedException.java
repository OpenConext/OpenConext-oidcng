package oidc.exceptions;

public class CookiesNotSupportedException extends BaseException {
    public CookiesNotSupportedException() {

        super("There is no savedRequest or cookies are not supported");
    }

    public CookiesNotSupportedException(String message) {
        super(message);
    }

    @Override
    protected boolean suppressStackTrace() {
        return true;
    }


}
