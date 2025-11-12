package oidc.endpoints;

import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import oidc.model.OpenIDClient;
import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SecureEndpointTest {

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final SecureRandom secureRandom = new SecureRandom();

    @Test
    public void secretsMatch() {
        String secret = UUID.randomUUID().toString();
        String encoded = passwordEncoder.encode(secret);

        OpenIDClient openIDClient = new OpenIDClient();
        ReflectionTestUtils.setField(openIDClient, "secret", encoded);

        SecureEndpoint secureEndpoint = new SecureEndpoint();
        PlainClientSecret plainClientSecret = new ClientSecretBasic(new ClientID("test"), new Secret(secret));

        boolean matches = secureEndpoint.secretsMatch(plainClientSecret, openIDClient);
        assertTrue(matches);
    }

    @Test
    public void longSecrets() {
        int numBytes = 54;// Because of base64 encoding, this will become 72 bytes (54 * 4 / 3 = 72);
        byte[] randomBytes = new byte[numBytes];
        secureRandom.nextBytes(randomBytes);
        String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        assertEquals(72, secret.getBytes().length);
        //must not be larger the 72, otherwise the encoding fails
        String encoded = passwordEncoder.encode(secret);
        OpenIDClient openIDClient = new OpenIDClient();
        ReflectionTestUtils.setField(openIDClient, "secret", encoded);

        SecureEndpoint secureEndpoint = new SecureEndpoint();
        ClientID clientID = new ClientID("test");
        Secret theSecret = new Secret(secret +
            "does_not_matter_anymore_only_the_first_72_bytes_are used");
        PlainClientSecret plainClientSecret = new ClientSecretBasic(clientID, theSecret);

        boolean matches = secureEndpoint.secretsMatch(plainClientSecret, openIDClient);
        assertTrue(matches);
    }

    @Test
    public void existingLongSecrets() {
        String secret = "AsNZ_H_IvWj_z19o7thTO_S83MOEWWSJ_Hiwt4Ms2qMEvPpvMia7SwbsvCLcLIu9h5rdEMYHFGsJD0eTcH0sRjj4OhghMlgfJQ";
        assertTrue(secret.getBytes().length > 72);

        String encoded = "$2a$10$F1eD3M74d3BS5FnI1moxme89R6rE/doNNhDpeIH9NgJWfF6lQRTd6";
        OpenIDClient openIDClient = new OpenIDClient();
        ReflectionTestUtils.setField(openIDClient, "secret", encoded);

        SecureEndpoint secureEndpoint = new SecureEndpoint();
        ClientID clientID = new ClientID("test");
        Secret theSecret = new Secret(secret);
        PlainClientSecret plainClientSecret = new ClientSecretBasic(clientID, theSecret);

        boolean matches = secureEndpoint.secretsMatch(plainClientSecret, openIDClient);
        assertTrue(matches);
    }

}
