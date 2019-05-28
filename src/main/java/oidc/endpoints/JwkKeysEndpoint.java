package oidc.endpoints;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import net.minidev.json.JSONObject;
import oidc.secure.TokenGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.Map;

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

    @GetMapping(value = {"/oidc/certs"}, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public String publishClientJwk() {
        return new JWKSet(tokenGenerator.getAllPublicKeys()).toJSONObject().toString();
    }

    @GetMapping("oidc/generate-secret-key-set")
    public Map<String, Object> generateSymmetricSecretKey() throws GeneralSecurityException, IOException {
        KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_CTR_HMAC_SHA256);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(outputStream));
        return objectMapper.readValue(outputStream.toString(), mapTypeReference);
    }

    @GetMapping("oidc/.well-known/openid-configuration")
    public Map<String, Object> wellKnownConfiguration() {
        return this.wellKnownConfiguration;
    }


}
