package oidc.exceptions;

public class UnsupportedJWTException extends RuntimeException {
    public UnsupportedJWTException(String message) {
        super(message);
    }
}
