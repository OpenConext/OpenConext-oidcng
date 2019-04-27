package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeySourceException;
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
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.GrantType;
import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.*;

public class TokenEndpointTest extends AbstractIntegrationTest {

    @Test
    @SuppressWarnings("unchecked")
    public void token() throws MalformedURLException, ParseException, JOSEException, BadJOSEException {
        String code = doAuthorize();
        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .auth()
                .preemptive()
                .basic("http@//mock-sp", "secret")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("code", code)
                .post("oidc/token")
                .as(Map.class);
        assertEquals(new Integer(5 * 60), body.get("expires_in"));

        String idToken = (String) body.get("id_token");
        verifySignedJWT(idToken);
        JWTClaimsSet claimsSet = processToken(idToken);

        assertEquals(Collections.singletonList("http@//mock-sp"), claimsSet.getAudience());
    }

    //Duplicated code - documentation reasons
    private JWTClaimsSet processToken(String token) throws ParseException, MalformedURLException, BadJOSEException, JOSEException {
        JWKSource keySource = new RemoteJWKSet(new URL("http://localhost:" + port + "/oidc/certs"));
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
        JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor.process(token, null);
    }

    //Duplicated code - documentation reasons
    private void verifySignedJWT(String token) throws MalformedURLException, JOSEException, ParseException {
        JWKSource keySource = new RemoteJWKSet(new URL("http://localhost:" + port + "/oidc/certs"));
        List<JWK> list = keySource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
        assertEquals(1, list.size());

        RSAKey rsaKey = (RSAKey) list.get(0);
        assertFalse(rsaKey.isPrivate());

        JWSVerifier verifier = new RSASSAVerifier(rsaKey);
        SignedJWT signedJWT = SignedJWT.parse(token);
        boolean verified = signedJWT.verify(verifier);

        assertTrue(verified);
    }
}