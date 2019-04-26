package oidc.exceptions;

public class CodeVerifierMissingException extends RuntimeException {
    public CodeVerifierMissingException(String message) {
        super(message);
    }
}
