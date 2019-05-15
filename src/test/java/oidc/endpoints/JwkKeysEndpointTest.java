package oidc.endpoints;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import oidc.AbstractIntegrationTest;
import oidc.secure.TokenGenerator;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class JwkKeysEndpointTest extends AbstractIntegrationTest {

    @Value("${spring.security.saml2.service-provider.entity-id}")
    private String issuer;

    @Test
    public void generate() throws ParseException, JsonProcessingException {
        Map<String, Object> res = getMapFromEndpoint("oidc/generate-jwks-keystore");
        assertRSAKey(res, true);
    }

    @Test
    public void publishClientJwk() throws ParseException, JsonProcessingException {
        Map<String, Object> res = getMapFromEndpoint("oidc/certs");
        assertRSAKey(res, false);
    }

    @Test
    public void wellKnownConfiguration() {
        Map<String, Object> res = getMapFromEndpoint("oidc/.well-known/openid-configuration");
        assertEquals(issuer, res.get("issuer"));
    }

    @Test
    public void generateSecretKeySet() {
        Map<String, Object> res = getMapFromEndpoint("oidc/generate-secret-key-set");
        assertTrue(res.containsKey("key"));
    }

    private void assertRSAKey(Map<String, Object> res, boolean isPrivate) throws ParseException, JsonProcessingException {
        List<JWK> jwkList = JWKSet.parse(objectMapper.writeValueAsString(res)).getKeys();
        assertEquals(1, jwkList.size());

        RSAKey rsaKey = (RSAKey) jwkList.get(0);
        assertEquals(isPrivate, rsaKey.isPrivate());
        assertEquals(TokenGenerator.signingAlg, rsaKey.getAlgorithm());
    }

    private Map<String, Object> getMapFromEndpoint(String path) {
        return given().when().get(path).as(mapTypeRef);
    }

}