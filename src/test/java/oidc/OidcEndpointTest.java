package oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public interface OidcEndpointTest {

    default JWTClaimsSet processToken(String token, int port) throws ParseException, MalformedURLException, BadJOSEException, JOSEException {
        JWKSource keySource = new RemoteJWKSet(new URL("http://localhost:" + port + "/oidc/certs"));
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
        JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor.process(token, null);
    }

    default JWTClaimsSet verifySignedJWT(String token, int port) throws MalformedURLException, JOSEException, ParseException {
        JWKSource keySource = new RemoteJWKSet(new URL("http://localhost:" + port + "/oidc/certs"));
        List<JWK> list = keySource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
        assertEquals(1, list.size());

        RSAKey rsaKey = (RSAKey) list.get(0);
        assertFalse(rsaKey.isPrivate());

        JWSVerifier verifier = new RSASSAVerifier(rsaKey);
        SignedJWT signedJWT = SignedJWT.parse(token);
        boolean verified = signedJWT.verify(verifier);

        assertTrue(verified);
        return signedJWT.getJWTClaimsSet();
    }

}
