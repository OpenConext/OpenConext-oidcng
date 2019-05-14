package oidc.endpoints;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import net.minidev.json.JSONObject;
import oidc.secure.TokenGenerator;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
public class JwkKeysEndpoint implements MapTypeReference {

    private TokenGenerator tokenGenerator;
    private Map<String, Object> wellKnownConfiguration;
    private ObjectMapper objectMapper;

    public JwkKeysEndpoint(TokenGenerator tokenGenerator,
                           ObjectMapper objectMapper,
                           @Value("${spring.security.saml2.service-provider.base-path}") String basePath,
                           @Value("${spring.security.saml2.service-provider.entity-id}") String issuer) throws IOException {
        this.tokenGenerator = tokenGenerator;
        String json = IOUtils.toString(new ClassPathResource("openid-configuration.json").getInputStream(), Charset.defaultCharset());
        json = json.replaceAll("@@base_url@@", basePath).replaceAll("@@issuer@@", issuer);
        this.wellKnownConfiguration = objectMapper.readValue(json, mapTypeReference);
        this.objectMapper = objectMapper;
    }

    @GetMapping("oidc/generate-jwks-keystore")
    public Map<String, List<JSONObject>> generate() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        com.nimbusds.jose.jwk.RSAKey build = new com.nimbusds.jose.jwk.RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .algorithm(new Algorithm("RS256"))
                .keyID("oidc")
                .build();

        return Collections.singletonMap("keys", Collections.singletonList(build.toJSONObject()));
    }

    @GetMapping("oidc/generate-secret-key-set")
    public Map<String, Object> generateSymmetricSecretKey() throws GeneralSecurityException, IOException {
        KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_CTR_HMAC_SHA256);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(outputStream));
        return objectMapper.readValue(outputStream.toString(), mapTypeReference);
    }

    @GetMapping(value = {"/oidc/certs"}, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public String publishClientJwk() {
        Map<String, ? extends JWK> allPublicKeys = tokenGenerator.getAllPublicKeys();
        return new JWKSet(new ArrayList<>(allPublicKeys.values())).toString();
    }

    @GetMapping("oidc/.well-known/openid-configuration")
    public Map<String, Object> wellKnownConfiguration() {
        return this.wellKnownConfiguration;
    }

}
