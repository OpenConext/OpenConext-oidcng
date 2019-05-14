package oidc.secure;

import oidc.AbstractIntegrationTest;
import oidc.model.OpenIDClient;
import oidc.model.User;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class TokenGeneratorTest extends AbstractIntegrationTest {

    @Autowired
    private TokenGenerator subject;

    @Test
    public void generateAccessTokenWithEmbeddedUserInfo() throws IOException {
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
    }

    private Map<String, Object> getUserInfo() throws IOException {
        return objectMapper.readValue(new ClassPathResource("oidc/userinfo_endpoint.json").getInputStream(), mapTypeReference);
    }

}