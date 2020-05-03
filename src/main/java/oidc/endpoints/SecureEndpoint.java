package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import oidc.exceptions.JWTAuthorizationGrantsException;
import oidc.model.OpenIDClient;
import oidc.secure.JWTRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Date;

public class SecureEndpoint {

    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    //See https://www.pivotaltracker.com/story/show/165565558
    boolean secretsMatch(PlainClientSecret clientSecret, OpenIDClient openIDClient) {
        return passwordEncoder.matches(clientSecret.getClientSecret().getValue(), openIDClient.getSecret());
    }

}
