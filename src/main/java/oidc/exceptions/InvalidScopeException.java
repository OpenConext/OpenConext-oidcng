package oidc.exceptions;

public class InvalidScopeException extends RuntimeException {
    public InvalidScopeException(String message) {
        super(message);
    }
}
