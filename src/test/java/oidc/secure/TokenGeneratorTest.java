package oidc.secure;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import oidc.AbstractIntegrationTest;
import oidc.exceptions.InvalidSignatureException;
import oidc.model.OpenIDClient;
import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import oidc.model.User;
import oidc.repository.SigningKeyRepository;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class TokenGeneratorTest extends AbstractIntegrationTest {

    @Autowired
    private SigningKeyRepository signingKeyRepository;

    @Test
    public void encryptAndDecryptAccessToken() throws IOException {
        doEncryptAndDecryptAccessToken();
    }

    @Test(expected = InvalidSignatureException.class)
    public void encryptAndDecryptAccessTokenTampered() throws IOException, ParseException, JOSEException {
        String accessToken = doEncryptAndDecryptAccessToken();

        SignedJWT signedJWT = SignedJWT.parse(accessToken);
        SignedJWT tamperedJWT = new SignedJWT(signedJWT.getHeader(), signedJWT.getJWTClaimsSet());
        tamperedJWT.sign(new RSASSASigner(new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS).generate()));
        tokenGenerator.decryptAccessTokenWithEmbeddedUserInfo(tamperedJWT.serialize());
    }

    @Test
    public void rolloverSigningKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
        resetAndCreateSigningKeys(3);
        SigningKey signingKey = signingKeyRepository.findAllByOrderByCreatedDesc().get(0);
        assertEquals("key_3", signingKey.getKeyId());
    }

    @Test
    public void onApplicationEvent() {
        mongoTemplate.findAllAndRemove(new Query(), SigningKey.class);
        mongoTemplate.findAllAndRemove(new Query(), SymmetricKey.class);

        tokenGenerator.onApplicationEvent(null);

        assertEquals(1, mongoTemplate.count(new Query(), SigningKey.class));
        assertEquals(1, mongoTemplate.count(new Query(), SymmetricKey.class));
    }

    private String doEncryptAndDecryptAccessToken() throws IOException {
        User user = new User("sub", "unspecifiedNameId", "http://mockidp", "clientId", getUserInfo());

        String clientId = "mock-sp";
        OpenIDClient client = mongoTemplate.find(Query.query(Criteria.where("clientId").is(clientId)), OpenIDClient.class).get(0);

        String accessToken = tokenGenerator.generateAccessTokenWithEmbeddedUserInfo(user, client);
        User convertedUser = tokenGenerator.decryptAccessTokenWithEmbeddedUserInfo(accessToken);

        assertEquals(user, convertedUser);

        return accessToken;
    }

    private Map<String, Object> getUserInfo() throws IOException {
        return objectMapper.readValue(new ClassPathResource("oidc/userinfo_endpoint.json").getInputStream(), mapTypeReference);
    }

}