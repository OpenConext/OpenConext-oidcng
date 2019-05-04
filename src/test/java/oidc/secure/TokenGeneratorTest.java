package oidc.secure;

import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.jose.JOSEException;
import oidc.TestUtils;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class TokenGeneratorTest implements TestUtils {

    private TokenGenerator subject = new TokenGenerator("issuer",
            "cNZsJwxJQVOpGAu7Lr8NMSlMLczyz0rwruN6s8Kobjw=");

    public TokenGeneratorTest() throws ParseException, JOSEException, IOException {
    }

    @Test
    public void generateEncryptedAccessToken() throws IOException, JOSEException, ParseException {
        Map<String, Object> data = getUserInfo();
        String jweString = subject.generateEncryptedAccessToken(data);

        Map<String, Object> parsed = subject.decryptAccessToken(jweString);
        assertEquals(data, parsed);
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