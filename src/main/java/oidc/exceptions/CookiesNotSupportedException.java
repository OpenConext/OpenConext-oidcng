package oidc.exceptions;

public class CookiesNotSupportedException extends BaseException {
    public CookiesNotSupportedException() {
        super("Cookies not supported");
    }
}
