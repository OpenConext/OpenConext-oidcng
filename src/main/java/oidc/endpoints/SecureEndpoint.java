package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import oidc.exceptions.JWTAuthorizationGrantsException;
import oidc.model.OpenIDClient;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.text.ParseException;
import java.util.Date;

public class SecureEndpoint {

    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    //See https://www.pivotaltracker.com/story/show/165565558
    boolean secretsMatch(PlainClientSecret clientSecret, OpenIDClient openIDClient) {
        return passwordEncoder.matches(clientSecret.getClientSecret().getValue(), openIDClient.getSecret());
    }

    boolean verifySignature(ClientSecretJWT clientSecretJWT, OpenIDClient openIDClient, String tokenEndpoint) throws JOSEException, ParseException {
        JWSVerifier verifier = new MACVerifier(openIDClient.getClientSecretJWT());
        SignedJWT clientAssertion = clientSecretJWT.getClientAssertion();
        JWTClaimsSet claimsSet = clientAssertion.getJWTClaimsSet();
        //https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-10
        if (!openIDClient.getClientId().equals(claimsSet.getIssuer())) {
            throw new JWTAuthorizationGrantsException("Invalid issuer");
        }
        if (!openIDClient.getClientId().equals(claimsSet.getSubject())) {
            throw new JWTAuthorizationGrantsException("Invalid subject");
        }
        if (!claimsSet.getAudience().contains(tokenEndpoint)) {
            throw new JWTAuthorizationGrantsException("Invalid audience");
        }
        if (new Date().after(claimsSet.getExpirationTime())) {
            throw new JWTAuthorizationGrantsException("Expired claims");
        }
        return clientAssertion.verify(verifier);
    }
}
