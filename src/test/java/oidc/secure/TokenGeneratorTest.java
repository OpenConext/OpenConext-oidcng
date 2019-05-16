package oidc.secure;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import oidc.AbstractIntegrationTest;
import oidc.exceptions.InvalidSignatureException;
import oidc.model.OpenIDClient;
import oidc.model.User;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;

import java.io.IOException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class TokenGeneratorTest extends AbstractIntegrationTest {

    @Autowired
    private TokenGenerator subject;

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
        subject.decryptAccessTokenWithEmbeddedUserInfo(tamperedJWT.serialize());
    }

    private String doEncryptAndDecryptAccessToken() throws IOException {
        User user = new User("sub", "unspecifiedNameId", "http://mockidp", "clientId", getUserInfo());

        String clientId = "http@//mock-sp";
        OpenIDClient client = mongoTemplate.find(Query.query(Criteria.where("clientId").is(clientId)), OpenIDClient.class).get(0);

        List<String> scopes = Arrays.asList("openid", "groups");
        String accessToken = subject.generateAccessTokenWithEmbeddedUserInfo(user, client, scopes);

        Map<String, Object> userInfo = subject.decryptAccessTokenWithEmbeddedUserInfo(accessToken);

        assertEquals(String.join(",", scopes), userInfo.get("scope"));
        assertEquals(clientId, userInfo.get("client_id"));

        User convertedUser = (User) userInfo.get("user");

        assertEquals(user, convertedUser);

        return accessToken;
    }

    private Map<String, Object> getUserInfo() throws IOException {
        return objectMapper.readValue(new ClassPathResource("oidc/userinfo_endpoint.json").getInputStream(), mapTypeReference);
    }

}