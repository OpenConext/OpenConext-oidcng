package oidc.endpoints;

import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import oidc.model.OpenIDClient;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class SecureEndpoint {

    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    //See https://www.pivotaltracker.com/story/show/165565558
    boolean secretsMatch(PlainClientSecret clientSecret, OpenIDClient openIDClient) {
        return passwordEncoder.matches(clientSecret.getClientSecret().getValue(), openIDClient.getSecret());
    }

}
