package oidc;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import io.restassured.RestAssured;
import io.restassured.mapper.TypeRef;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import oidc.endpoints.MapTypeReference;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.OpenIDClient;
import oidc.model.RefreshToken;
import oidc.model.Sequence;
import oidc.model.SigningKey;
import oidc.secure.TokenGenerator;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.mongodb.core.BulkOperations;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


/**
 * Override the @ActiveProfiles annotation if you don't want to have mock SAML authentication
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.data.mongodb.uri=mongodb://127.0.0.1:27017/oidc_test",
                "mongodb_db=oidc_test",
                "cron.node-cron-job-responsible=false"
        })
@ActiveProfiles("dev")
public abstract class AbstractIntegrationTest implements TestUtils, MapTypeReference {

    @LocalServerPort
    protected int port;

    @Autowired
    protected MongoTemplate mongoTemplate;

    @Autowired
    protected TokenGenerator tokenGenerator;

    @Autowired
    protected ObjectMapper objectMapper;

    protected TypeRef<Map<String, Object>> mapTypeRef = new TypeRef<Map<String, Object>>() {
    };

    private List<OpenIDClient> openIDClients;

    @Before
    public void before() throws IOException {
        RestAssured.port = port;
        mongoTemplate.bulkOps(BulkOperations.BulkMode.ORDERED, OpenIDClient.class)
                .remove(new Query())
                .insert(openIDClients())
                .execute();
    }

    protected List<OpenIDClient> openIDClients() throws IOException {
        if (CollectionUtils.isEmpty(this.openIDClients)) {
            this.openIDClients = relyingParties().stream().map(OpenIDClient::new).collect(Collectors.toList());
        }
        return this.openIDClients;
    }

    protected OpenIDClient openIDClient() throws IOException {
        return this.openIDClients().get(0);
    }

    protected List<Map<String, Object>> relyingParties() throws IOException {
        return objectMapper.readValue(new ClassPathResource("manage/oidc10_rp.json").getInputStream(),
                new TypeReference<List<Map<String, Object>>>() {
                });
    }

    protected String doAuthorize() throws UnsupportedEncodingException {
        Response response = doAuthorize("mock-sp", "code", null, null, null);
        assertEquals(302, response.getStatusCode());

        return getCode(response);
    }

    protected void resetAndCreateSigningKeys(int numberOfSigningKeys) throws NoSuchProviderException, NoSuchAlgorithmException {
        mongoTemplate.dropCollection(Sequence.class);
        mongoTemplate.dropCollection(SigningKey.class);
        for (int i = 1; i < numberOfSigningKeys + 1; i++) {
            SigningKey signingKey = tokenGenerator.rolloverSigningKeys();
            assertEquals("key_" + i, signingKey.getKeyId());
        }
    }

    protected JWTClaimsSet processToken(String token, int port) throws ParseException, MalformedURLException, BadJOSEException, JOSEException {
        JWKSource keySource = new RemoteJWKSet(new URL("http://localhost:" + port + "/oidc/certs"));
        JWSKeySelector keySelector = new JWSVerificationKeySelector(TokenGenerator.signingAlg, keySource);
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor.process(token, null);
    }

    protected JWTClaimsSet verifySignedJWT(String token, int port) throws MalformedURLException, JOSEException, ParseException {
        JWKSource keySource = new RemoteJWKSet(new URL("http://localhost:" + port + "/oidc/certs"));
        List<JWK> list = keySource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);

        SignedJWT signedJWT = SignedJWT.parse(token);

        RSAKey rsaKey = (RSAKey) list.stream().filter(jwk -> jwk.getKeyID().equals(signedJWT.getHeader().getKeyID())).findAny().get();
        assertFalse(rsaKey.isPrivate());

        JWSVerifier verifier = new RSASSAVerifier(rsaKey);
        boolean verified = signedJWT.verify(verifier);

        assertTrue(verified);
        return signedJWT.getJWTClaimsSet();
    }

    protected String getCode(Response response) {
        String location = response.getHeader("Location");
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(location);
        return builder.build().getQueryParams().getFirst("code");
    }

    protected Response doAuthorize(String clientId, String responseType, String responseMode, String nonce, String codeChallenge) throws UnsupportedEncodingException {
        return doAuthorizeWithClaims(clientId, responseType, responseMode, nonce, codeChallenge, Collections.emptyList());
    }

    protected Response doAuthorizeWithClaims(String clientId, String responseType, String responseMode, String nonce, String codeChallenge,
                                             List<String> claims) {
        return doAuthorizeWithClaimsAndScopes(clientId, responseType, responseMode, nonce, codeChallenge, claims, "openid profile", "example");
    }

    protected String doAuthorizeWithScopes(String clientId, String responseType, String responseMode, String scopes) throws UnsupportedEncodingException {
        return getCode(doAuthorizeWithClaimsAndScopes(clientId, responseType, responseMode, null, null, null, scopes, "example"));
    }

    protected Response doAuthorizeWithClaimsAndScopes(String clientId, String responseType, String responseMode,
                                                      String nonce, String codeChallenge, List<String> claims,
                                                      String scopes, String state) {
        return doAuthorizeWithClaimsAndScopesAndCodeChallengeMethod(clientId, responseType, responseMode, nonce, codeChallenge, claims, scopes, state, CodeChallengeMethod.PLAIN.getValue());
    }

    protected Response doAuthorizeWithClaimsAndScopesAndCodeChallengeMethod(String clientId, String responseType,
                                                                          String responseMode, String nonce,
                                                                          String codeChallenge, List<String> claims,
                                                                          String scopes, String state, String codeChallengeMethod) {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", scopes);
        queryParams.put("response_type", responseType);
        queryParams.put("client_id", clientId);
        queryParams.put("redirect_uri", "http%3A%2F%2Flocalhost%3A8080");
        queryParams.put("state", state);
        if (StringUtils.hasText(responseMode)) {
            queryParams.put("response_mode", responseMode);
        }
        if (StringUtils.hasText(nonce)) {
            queryParams.put("nonce", nonce);
        }
        if (StringUtils.hasText(codeChallenge)) {
            queryParams.put("code_challenge", codeChallenge);
            queryParams.put("code_challenge_method", codeChallengeMethod);
        }
        if (!CollectionUtils.isEmpty(claims)) {
            ClaimsRequest claimsRequest = new ClaimsRequest();
            claims.forEach(claim -> claimsRequest.addIDTokenClaim(claim));
            String claimsRequestString = claimsRequest.toString();
            queryParams.put("claims", claimsRequestString);
        }
        Response response = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize");
        return response;
    }

    protected Map<String, Object> doToken(String code) {
        return doToken(code, "mock-sp", "secret", GrantType.AUTHORIZATION_CODE);
    }

    protected Map<String, Object> doToken(String code, String clientId, String secret, GrantType grantType) {
        return doToken(code, clientId, secret, grantType, null);
    }

    protected Map<String, Object> doToken(String code, String clientId, String secret, GrantType grantType, String codeVerifier) {
        RequestSpecification header = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded");
        if (StringUtils.hasText(clientId) && StringUtils.hasText(secret)) {
            header = header.auth().preemptive().basic(clientId, secret);
        }
        if (StringUtils.hasText(clientId) && StringUtils.isEmpty(secret)) {
            header = header.formParam("client_id", clientId);
        }
        if (StringUtils.hasText(codeVerifier)) {
            header = header.formParam("code_verifier", codeVerifier);
        }
        if (StringUtils.hasText(code)) {
            header = header.formParam("code", code);
        }
        return header
                .formParam("grant_type", grantType.getValue())
                .post("oidc/token")
                .as(Map.class);
    }

    protected void expireAccessToken(String token) {
        doExpire(token, AccessToken.class);
    }

    protected void expireRefreshToken(String token) {
        doExpire(token, RefreshToken.class);
    }

    protected void expireAuthorizationCode(String code) {
        doExpireWithFindProperty(code, AuthorizationCode.class, "code");
    }

    private <T> void doExpire(String token, Class<T> clazz) {
        doExpireWithFindProperty(token, clazz, "innerValue");
    }

    private <T> void doExpireWithFindProperty(String token, Class<T> clazz, String property) {
        Object o = mongoTemplate.find(Query.query(Criteria.where(property).is(token)), clazz).get(0);
        Date expiresIn = Date.from(LocalDateTime.now().minusYears(1L).atZone(ZoneId.systemDefault()).toInstant());
        ReflectionTestUtils.setField(o, "expiresIn", expiresIn);
        mongoTemplate.save(o);
    }
}
