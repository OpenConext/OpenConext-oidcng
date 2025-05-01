package oidc.crypto;

import lombok.SneakyThrows;
import org.jasypt.util.text.AES256TextEncryptor;

import java.util.UUID;

public class SimpleEncryptionHandler {

    private final static AES256TextEncryptor encryptor = new AES256TextEncryptor();

    static {
        encryptor.setPassword(UUID.randomUUID().toString());
    }

    private SimpleEncryptionHandler() {
    }

    @SneakyThrows
    public static String encrypt(String data) {
        return encryptor.encrypt(data);
    }

    @SneakyThrows
    public static String decrypt(String encryptedData) {
        return encryptor.decrypt(encryptedData);
    }
}
