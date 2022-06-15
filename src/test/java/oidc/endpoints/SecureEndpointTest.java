package oidc.endpoints;

import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import oidc.model.OpenIDClient;
import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.UUID;

import static org.junit.Assert.assertTrue;

public class SecureEndpointTest {

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Test
    public void secretsMatch() {
        String secret = UUID.randomUUID().toString();
        String encoded = passwordEncoder.encode(secret);

        OpenIDClient openIDClient = new OpenIDClient();
        ReflectionTestUtils.setField(openIDClient, "secret", encoded);

        SecureEndpoint secureEndpoint = new SecureEndpoint();
        PlainClientSecret plainClientSecret = new ClientSecretBasic(new ClientID("test"), new Secret(secret));

        long now = System.currentTimeMillis();
        boolean matches = secureEndpoint.secretsMatch(plainClientSecret, openIDClient);
        System.out.println(System.currentTimeMillis() - now);
        assertTrue(matches);
    }
}