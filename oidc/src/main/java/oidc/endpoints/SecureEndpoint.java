package oidc.endpoints;

import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.auth.Secret;
import oidc.model.OpenIDClient;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Arrays;

public class SecureEndpoint {

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    boolean secretsMatch(PlainClientSecret clientSecret, OpenIDClient openIDClient) {
        //See https://github.com/OpenConext/OpenConext-oidcng/issues/286
        String secret = clientSecret.getClientSecret().getValue();
        if (secret.getBytes().length > 72) {
            byte[] first72bytes =  Arrays.copyOf(secret.getBytes(), 72);
            secret = new String(first72bytes);
        }
        return passwordEncoder.matches(secret, openIDClient.getSecret());
    }

}
