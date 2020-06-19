package oidc.crypto;

import org.bouncycastle.jcajce.provider.symmetric.AES;
import org.junit.Test;

import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class KeyGeneratorTest {

    @Test
    public void generateKeys() throws Exception {
        String[] keys = KeyGenerator.generateKeys();

        assertTrue(keys[0].startsWith("-----BEGIN RSA PRIVATE KEY-----"));
        assertTrue(keys[0].endsWith("-----END RSA PRIVATE KEY-----\n"));

        assertTrue(keys[1].startsWith("-----BEGIN CERTIFICATE-----"));
        assertTrue(keys[1].endsWith("-----END CERTIFICATE-----\n"));
    }

    @Test
    public void oneWayHash() {
        String s = "urn:collab:person:eduid.nl:7d4fca9b-2169-4d55-8347-73cf29b955a2";
        String secret = "RQeRwezeKDDHkofeja8fiefG";

        assertEquals(KeyGenerator.oneWayHash(s, secret), KeyGenerator.oneWayHash(s, secret));
        assertEquals(128, KeyGenerator.oneWayHash(s, secret).getBytes().length);
    }

}