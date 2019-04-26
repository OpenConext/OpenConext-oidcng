package oidc.exceptions;

public class InvalidGrantException extends RuntimeException {
    public InvalidGrantException(String message) {
        super(message);
    }
}
