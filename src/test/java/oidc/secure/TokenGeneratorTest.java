package oidc.secure;

import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.jose.JOSEException;
import io.restassured.mapper.TypeRef;
import oidc.TestUtils;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.text.ParseException;
import java.util.Map;

import static org.junit.Assert.*;

public class TokenGeneratorTest implements TestUtils {

    private TokenGenerator subject= new TokenGenerator("issuer");

    public TokenGeneratorTest() throws ParseException, JOSEException, IOException {
    }

    @Test
    public void generateEncryptedAccessToken() throws IOException, JOSEException, ParseException {
        Map<String, Object> data = objectMapper.readValue(new ClassPathResource("oidc/userinfo_endpoint.json").getInputStream(), new TypeReference<Map<String, Object>>() {
        });
        String jweString = subject.generateEncryptedAccessToken(data);

        Map<String, Object> parsed = subject.decryptAccessToken(jweString);
        assertEquals(data, parsed);
    }
}