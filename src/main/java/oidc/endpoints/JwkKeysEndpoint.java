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
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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

    private TokenGenerator tokenGenerator;
    private ObjectMapper objectMapper;
    private Map<String, Object> wellKnownConfiguration;

    public JwkKeysEndpoint(TokenGenerator tokenGenerator,
                           ObjectMapper objectMapper,
                           @Value("${openid_configuration_path}") Resource configurationPath) throws IOException {
        this.tokenGenerator = tokenGenerator;
        this.wellKnownConfiguration = objectMapper.readValue(configurationPath.getInputStream(), mapTypeReference);
        this.objectMapper = objectMapper;
    }

    @GetMapping(value = {"/oidc/certs"}, produces = MediaType.APPLICATION_JSON_VALUE)
    public String publishClientJwk() throws GeneralSecurityException, ParseException, IOException {
        String s = new JWKSet(tokenGenerator.getAllPublicKeys()).toString();
        return s;
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
