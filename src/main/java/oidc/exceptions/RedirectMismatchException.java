package oidc.exceptions;

public class RedirectMismatchException extends RuntimeException {
    public RedirectMismatchException(String message) {
        super(message);
    }
}
