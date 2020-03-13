package oidc.crypto;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class KeyGeneratorTest {

    private KeyGenerator keyGenerator = new KeyGenerator();

    @Test
    public void generateKeys() throws Exception {
        String[] keys = keyGenerator.generateKeys();

        assertTrue(keys[0].startsWith("-----BEGIN RSA PRIVATE KEY-----"));
        assertTrue(keys[0].endsWith("-----END RSA PRIVATE KEY-----\n"));

        assertTrue(keys[1].startsWith("-----BEGIN CERTIFICATE-----"));
        assertTrue(keys[1].endsWith("-----END CERTIFICATE-----\n"));
    }
}