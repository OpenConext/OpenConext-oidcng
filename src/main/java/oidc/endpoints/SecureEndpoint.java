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

    boolean verifySignature(JWTAuthentication jwtAuthentication, OpenIDClient openIDClient, String tokenEndpoint)
            throws JOSEException, ParseException, CertificateException, IOException {
        JWSVerifier verifier = jwsVerifier(jwtAuthentication, openIDClient);
        SignedJWT clientAssertion = jwtAuthentication.getClientAssertion();
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

    private JWSVerifier jwsVerifier(JWTAuthentication jwtAuthentication, OpenIDClient openIDClient)
            throws JOSEException, IOException, ParseException, CertificateException {
        boolean isClientSecret = jwtAuthentication instanceof ClientSecretJWT;
        if (isClientSecret) {
            return new MACVerifier(openIDClient.getClientSecretJWT());
        }
        String signingCertificate = JWTRequest.getSigningCertificate(openIDClient);
        return new RSASSAVerifier(JWTRequest.rsaKey(signingCertificate));

    }

}
