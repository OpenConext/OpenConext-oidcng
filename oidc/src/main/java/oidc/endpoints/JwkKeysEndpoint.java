package oidc.endpoints;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AesCtrHmacAeadKeyManager;
import com.nimbusds.jose.jwk.JWKSet;
import oidc.secure.TokenGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
public class JwkKeysEndpoint implements MapTypeReference {

    private final TokenGenerator tokenGenerator;
    private final ObjectMapper objectMapper;
    private final Map<String, Object> wellKnownConfiguration;
    private final Long maxAge;

    public JwkKeysEndpoint(TokenGenerator tokenGenerator,
                           ObjectMapper objectMapper,
                           @Value("${keys-cache.cache-duration-seconds}") Long maxAge,
                           @Value("${openid_configuration_path}") Resource configurationPath) throws IOException {
        this.tokenGenerator = tokenGenerator;
        this.wellKnownConfiguration = objectMapper.readValue(configurationPath.getInputStream(), mapTypeReference);
        this.objectMapper = objectMapper;
        this.maxAge = maxAge;
    }

    @GetMapping(value = {"/oidc/certs"}, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> publishClientJwk() throws GeneralSecurityException, ParseException, IOException {
        String publicKeysJson = objectMapper.writeValueAsString(new JWKSet(tokenGenerator.getAllPublicKeys()).toJSONObject());
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setCacheControl(CacheControl.maxAge(this.maxAge, TimeUnit.SECONDS).noTransform());
        return ResponseEntity.ok()
                .headers(responseHeaders)
                .body(publicKeysJson);
    }

    @GetMapping("oidc/generate-secret-key-set")
    public Map<String, Object> generateSymmetricSecretKey() throws GeneralSecurityException, IOException {
        KeysetHandle keysetHandle = KeysetHandle.generateNew(AesCtrHmacAeadKeyManager.aes256CtrHmacSha256Template());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(outputStream));
        return objectMapper.readValue(outputStream.toString(), mapTypeReference);
    }

    @GetMapping({"oidc/.well-known/openid-configuration", ".well-known/openid-configuration"})
    public ResponseEntity<Map<String, Object>> wellKnownConfiguration() {
        return ResponseEntity.status(HttpStatus.OK)
                .cacheControl(CacheControl.maxAge(4, TimeUnit.HOURS).noTransform())
                .body(this.wellKnownConfiguration);
    }
}
