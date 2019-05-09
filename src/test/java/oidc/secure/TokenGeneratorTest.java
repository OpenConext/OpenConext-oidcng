package oidc.secure;

import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import oidc.TestUtils;
import oidc.exceptions.InvalidSignatureException;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class TokenGeneratorTest implements TestUtils {

    private TokenGenerator subject = new TokenGenerator(
            new ClassPathResource("oidc.keystore.jwks.json"),
            "issuer",
            "Y3nS5p0bKLI8bR/thxo0CFS3uItJXifjfRymRGOGJhRgij48ttTjPR33ZdAhobHrXd5MJNz4X69wYKvsUMlIfg==");

    public TokenGeneratorTest() throws ParseException, JOSEException, IOException {
    }

    @Test
    public void generateEncryptedAccessToken() throws IOException, JOSEException, ParseException {
        Map<String, Object> data = getUserInfo();
        String jweString = subject.generateEncryptedAccessToken(data);

        Map<String, Object> parsed = subject.decryptAccessToken(jweString);
        assertEquals(data, parsed);
    }

    @Test(expected = InvalidSignatureException.class)
    public void tamperWithEncryptedAccessToken() throws JOSEException, ParseException, NoSuchAlgorithmException {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), new JWTClaimsSet.Builder().build());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        signedJWT.sign(new RSASSASigner(keyPairGenerator.generateKeyPair().getPrivate()));
        subject.verifyClaims(signedJWT);
    }

    @Test
    public void generateSymmetricEncryptedAccessToken() throws IOException, JOSEException, ParseException {
        Map<String, Object> data = getUserInfo();
        String jweString = subject.generateSymmetricEncryptedAccessToken(data);

        Map<String, Object> parsed = subject.decryptSymmtricAccessToken(jweString);
        assertEquals(data, parsed);
    }

    private Map<String, Object> getUserInfo() throws IOException {
        return objectMapper.readValue(new ClassPathResource("oidc/userinfo_endpoint.json").getInputStream(),
                new TypeReference<Map<String, Object>>() {
                });
    }

}