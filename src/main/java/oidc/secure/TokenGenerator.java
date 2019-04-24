package oidc.secure;

import oidc.model.OpenIDClient;

import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;

public class TokenGenerator {

    private static char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            .toCharArray();

    private static Random random = new SecureRandom();

    public static String generateAccessToken() {
        return repositoryId();
    }

    public static String generateAuthorizationCode() {
        byte[] verifierBytes = new byte[8];
        random.nextBytes(verifierBytes);
        char[] chars = new char[verifierBytes.length];
        for (int i = 0; i < verifierBytes.length; i++) {
            chars[i] = DEFAULT_CODEC[((verifierBytes[i] & 0xFF) % DEFAULT_CODEC.length)];
        }
        return new String(chars);
    }

    public static String repositoryId() {
        return UUID.randomUUID().toString();
    }

}
