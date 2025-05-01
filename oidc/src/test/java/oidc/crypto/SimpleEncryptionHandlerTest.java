package oidc.crypto;

import org.jasypt.util.text.AES256TextEncryptor;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class SimpleEncryptionHandlerTest {

    @Test
    void flow() {
        String data = "1234-5678";
        String encrypted = SimpleEncryptionHandler.encrypt(data);
        String original = SimpleEncryptionHandler.decrypt(encrypted);
        assertEquals(data, original);

        String encryptedAgain = SimpleEncryptionHandler.encrypt(data);
        assertNotEquals(encrypted, encryptedAgain);

        String decryptedAgain = SimpleEncryptionHandler.decrypt(encryptedAgain);
        assertEquals(data, decryptedAgain);
    }

}