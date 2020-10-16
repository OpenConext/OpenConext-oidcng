package oidc.secure;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import oidc.AbstractIntegrationTest;

import oidc.model.EncryptedTokenValue;
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
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TokenGeneratorTest extends AbstractIntegrationTest {

    @Autowired
    private SigningKeyRepository signingKeyRepository;

    @Test
    public void encryptAndDecryptAccessToken() throws IOException {
        doEncryptAndDecryptAccessToken();
    }

    @Test(expected = JOSEException.class)
    public void encryptAndDecryptAccessTokenTampered() throws IOException, ParseException, JOSEException {
        String accessToken = doEncryptAndDecryptAccessToken();

        SignedJWT signedJWT = SignedJWT.parse(accessToken);
        SignedJWT tamperedJWT = new SignedJWT(signedJWT.getHeader(), signedJWT.getJWTClaimsSet());
        tamperedJWT.sign(new RSASSASigner(new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS).generate()));
        tokenGenerator.decryptAccessTokenWithEmbeddedUserInfo(tamperedJWT.serialize());
    }

    @Test
    public void rolloverSigningKeys() throws GeneralSecurityException, ParseException, IOException {
        resetAndCreateSigningKeys(3);
        SigningKey signingKey = signingKeyRepository.findAllByOrderByCreatedDesc().get(0);
        assertTrue(signingKey.getKeyId().startsWith(currentSigningKeyIdPrefix()));
    }

    @Test
    public void onApplicationEvent() {
        mongoTemplate.findAllAndRemove(new Query(), SigningKey.class);
        mongoTemplate.findAllAndRemove(new Query(), SymmetricKey.class);

        tokenGenerator.onApplicationEvent(null);

        assertEquals(1, mongoTemplate.count(new Query(), SigningKey.class));
        assertEquals(1, mongoTemplate.count(new Query(), SymmetricKey.class));
    }

    @Test
    public void invalidAcrValueIsAllowed() throws IOException, ParseException {
        User user = new User("sub", "unspecifiedNameId", "http://mockidp",
                "clientId", getUserInfo(), Arrays.asList("http://test.surfconext.nl/assurance/loa3", "invalid_acr"));
        OpenIDClient client = openIDClient("mock-sp");
        String idToken = tokenGenerator.generateIDTokenForTokenEndpoint(Optional.of(user), client, "nonce", Collections.emptyList(), Optional.empty());
        SignedJWT jwt = SignedJWT.parse(idToken);
        Object acr = jwt.getJWTClaimsSet().getClaim("acr");
        assertEquals("http://test.surfconext.nl/assurance/loa3 invalid_acr", acr);
    }

    @Test
    public void defaultAcrValue() throws IOException, JOSEException, NoSuchAlgorithmException, NoSuchProviderException, ParseException {
        User user = new User("sub", "unspecifiedNameId", "http://mockidp",
                "clientId", getUserInfo(), Collections.emptyList());
        OpenIDClient client = openIDClient("mock-sp");
        String idToken = tokenGenerator.generateIDTokenForTokenEndpoint(Optional.of(user), client, "nonce", Collections.emptyList(), Optional.empty());
        SignedJWT jwt = SignedJWT.parse(idToken);
        Object acr = jwt.getJWTClaimsSet().getClaim("acr");
        assertEquals("http://test.surfconext.nl/assurance/loa1", acr);
    }

    @Test
    public void generateAuthorizationCode() {
        String authorizationCode = tokenGenerator.generateAuthorizationCode();
        assertEquals(12, authorizationCode.length());
    }

    private String doEncryptAndDecryptAccessToken() throws IOException {
        User user = new User("sub", "unspecifiedNameId", "http://mockidp",
                "clientId", getUserInfo(), Collections.emptyList());

        String clientId = "mock-sp";
        OpenIDClient client = mongoTemplate.find(Query.query(Criteria.where("clientId").is(clientId)), OpenIDClient.class).get(0);

        EncryptedTokenValue encryptedAccessToken = tokenGenerator.generateAccessTokenWithEmbeddedUserInfo(user, client);
        String accessToken = encryptedAccessToken.getValue();
        User convertedUser = tokenGenerator.decryptAccessTokenWithEmbeddedUserInfo(accessToken);

        assertEquals(user, convertedUser);

        return accessToken;
    }

    private Map<String, Object> getUserInfo() throws IOException {
        return objectMapper.readValue(new ClassPathResource("oidc/userinfo_endpoint.json").getInputStream(), mapTypeReference);
    }

}