package oidc.secure;

import oidc.AbstractIntegrationTest;
import oidc.model.SigningKey;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.junit.Assert.*;

public class KeyRolloverTest extends AbstractIntegrationTest {

    @Test
    public void clean() throws NoSuchProviderException, NoSuchAlgorithmException {
        resetAndCreateSigningKeys(0);
        KeyRollover rollover = new KeyRollover(tokenGenerator, true);
        rollover.clean();

        assertEquals(1, mongoTemplate.findAll(SigningKey.class).size());

    }
}