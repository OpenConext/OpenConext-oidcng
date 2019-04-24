package oidc.exceptions;

public class ClientAuthenticationNotSupported extends RuntimeException {
    public ClientAuthenticationNotSupported(String message) {
        super(message);
    }
}
