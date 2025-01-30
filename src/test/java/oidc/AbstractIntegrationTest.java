package oidc;


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
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import io.restassured.RestAssured;
import io.restassured.internal.http.URIBuilder;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import oidc.endpoints.MapTypeReference;
import oidc.model.*;
import oidc.repository.SequenceRepository;
import oidc.secure.TokenGenerator;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
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
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static java.util.Collections.emptyMap;
import static org.junit.Assert.*;


/**
 * Override the @ActiveProfiles annotation if you don't want to have mock SAML authentication
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "cron.node-cron-job-responsible=false",
                "eduid.uri=http://localhost:8099/attribute-manipulation"
        })
@ActiveProfiles("dev")
@SuppressWarnings("unchecked")
public abstract class AbstractIntegrationTest implements TestUtils, MapTypeReference {

    @LocalServerPort
    protected int port;

    @Autowired
    protected MongoTemplate mongoTemplate;

    @Autowired
    protected TokenGenerator tokenGenerator;

    @Autowired
    protected SequenceRepository sequenceRepository;

    private List<OpenIDClient> openIDClients;

    @Before
    public void before() throws IOException {
        RestAssured.port = port;
        mongoTemplate.bulkOps(BulkOperations.BulkMode.ORDERED, OpenIDClient.class)
                .remove(new Query())
                .insert(openIDClients())
                .execute();
        Arrays.asList(UserConsent.class, SigningKey.class, SymmetricKey.class, RefreshToken.class, AccessToken.class,
                AuthorizationCode.class, DeviceAuthorization.class)
                .forEach(clazz -> mongoTemplate.remove(new Query(), clazz));
    }

    protected List<OpenIDClient> openIDClients() throws IOException {
        if (CollectionUtils.isEmpty(this.openIDClients)) {
            this.openIDClients = relyingParties().stream().map(OpenIDClient::new).collect(Collectors.toList());
        }
        return this.openIDClients;
    }

    protected OpenIDClient openIDClient(String clientId) throws IOException {
        return this.openIDClients().stream()
                .filter(openIDClient -> openIDClient.getClientId().equals(clientId))
                .findAny()
                .orElseThrow(IllegalArgumentException::new);
    }

    protected String doAuthorize() throws IOException {
        Response response = doAuthorize("mock-sp", "code", null, null, null);
        assertEquals(302, response.getStatusCode());

        return getCode(response);
    }

    protected void resetAndCreateSigningKeys(int numberOfSigningKeys) throws GeneralSecurityException, ParseException, IOException {
        mongoTemplate.dropCollection(Sequence.class);
        mongoTemplate.dropCollection(SigningKey.class);
        for (int i = 1; i < numberOfSigningKeys + 1; i++) {
            SigningKey signingKey = tokenGenerator.rolloverSigningKeys();
            assertNotNull(signingKey.getKeyId());
        }
    }

    protected String currentSigningKeyIdPrefix() {
        return "key_" + new SimpleDateFormat("yyyy_MM_dd").format(new Date());
    }

    protected void resetAndCreateSymmetricKeys(int numberOfSymmetricKeys) throws GeneralSecurityException, IOException {
        mongoTemplate.dropCollection(SymmetricKey.class);
        for (int i = 1; i < numberOfSymmetricKeys + 1; i++) {
            SymmetricKey symmetricKey = tokenGenerator.rolloverSymmetricKeys();
            assertNotNull(symmetricKey.getKeyId());
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

    protected Response doAuthorize(String clientId, String responseType, String responseMode, String nonce, String codeChallenge) throws IOException {
        return doAuthorizeWithClaims(clientId, responseType, responseMode, nonce, codeChallenge, Collections.emptyList());
    }

    protected Response doAuthorizeWithClaims(String clientId, String responseType, String responseMode, String nonce, String codeChallenge,
                                             List<String> claims) throws IOException {
        return doAuthorizeWithClaimsAndScopes(clientId, responseType, responseMode, nonce, codeChallenge, claims, "openid", "example");
    }

    protected String doAuthorizeWithScopes(String clientId, String responseType, String responseMode, String scopes) throws IOException {
        return getCode(doAuthorizeWithClaimsAndScopes(clientId, responseType, responseMode, null, null, null, scopes, "example"));
    }

    protected Response doAuthorizeWithClaimsAndScopes(String clientId, String responseType, String responseMode,
                                                      String nonce, String codeChallenge, List<String> claims,
                                                      String scopes, String state) throws IOException {
        return doAuthorizeWithClaimsAndScopesAndCodeChallengeMethod(clientId, responseType, responseMode, nonce, codeChallenge, claims, scopes, state, CodeChallengeMethod.PLAIN.getValue());
    }

    protected Response doAuthorizeWithClaimsAndScopesAndCodeChallengeMethod(String clientId, String responseType,
                                                                            String responseMode, String nonce,
                                                                            String codeChallenge, List<String> claims,
                                                                            String scopes, String state, String codeChallengeMethod) throws IOException {
        return doAuthorizeQueryParameters(clientId, responseType, responseMode, nonce, codeChallenge, claims, scopes, state, codeChallengeMethod, null, null);
    }

    protected Response doAuthorizeWithJWTRequest(String clientId, String responseType, String responseMode,
                                                 JWT signedJWT, String requestURL) throws IOException {
        return doAuthorizeQueryParameters(clientId, responseType, responseMode, "nonce", null,
                null, "openid", "state", null, signedJWT, requestURL);
    }

    protected Response doAuthorizeQueryParameters(String clientId, String responseType, String responseMode,
                                                  String nonce, String codeChallenge, List<String> claims,
                                                  String scopes, String state, String codeChallengeMethod,
                                                  JWT signedJWT, String requestURL) throws IOException {
        Map<String, String> queryParams = new HashMap<>();
        if (StringUtils.hasText(scopes)) {
            queryParams.put("scope", URIBuilder.encode(scopes, Charset.defaultCharset().toString()));
        }
        //Ensure we don't end up with an invalid URI containing spaces
        queryParams.put("response_type", URIBuilder.encode(responseType, Charset.defaultCharset().toString()));
        queryParams.put("client_id", clientId);
        if (StringUtils.hasText(clientId)) {
            queryParams.put("redirect_uri", openIDClient(clientId).getRedirectUrls().get(0));
        }
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
            queryParams.put("claims", URIBuilder.encode(claimsRequestString, Charset.defaultCharset().toString()));
        }
        if (signedJWT != null) {
            queryParams.put("request", signedJWT.serialize());
        }
        if (StringUtils.hasText(requestURL)) {
            queryParams.put("request_uri", requestURL);
        }
        Response response = given()
                .urlEncodingEnabled(false)
                .redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize");
        return response;
    }

    protected Map<String, Object> doToken(String code) throws IOException {
        return doToken(code, "mock-sp", "secret", GrantType.AUTHORIZATION_CODE);
    }

    protected Map<String, Object> doToken(String code, String clientId, String secret, GrantType grantType) throws IOException {
        return doToken(code, clientId, secret, grantType, null);
    }

    protected Map<String, Object> doToken(String code, String clientId, String secret, GrantType grantType, String codeVerifier) throws IOException {
        RequestSpecification header = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded");
        if (StringUtils.hasText(clientId) && StringUtils.hasText(secret)) {
            header = header.auth().preemptive().basic(clientId, secret);
        }
        if (StringUtils.hasText(clientId) && StringUtils.isEmpty(secret)) {
            header = header.formParam("client_id", clientId);
        }
        if (StringUtils.hasText(clientId)) {
            header = header.formParam("redirect_uri", openIDClient(clientId).getRedirectUrls().get(0));
        }
        if (StringUtils.hasText(codeVerifier)) {
            header = header.formParam("code_verifier", codeVerifier);
        }
        if (StringUtils.hasText(code)) {
            header = header.formParam("code", code);
        }
        Response response = header
                .formParam("grant_type", grantType.getValue())
                .post("oidc/token");
        if (response.body() != null && !response.body().asString().isEmpty()) {
            return response.body().as(Map.class);
        }
        return Collections.emptyMap();
    }

    protected NodeList getNodeListFromFormPost(Response response) throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(new ByteArrayInputStream(response.asByteArray()));
        XPath xPath = XPathFactory.newInstance().newXPath();

        Node node = (Node) xPath.compile("//html/body/form").evaluate(doc, XPathConstants.NODE);
        assertNotNull(node.getAttributes().getNamedItem("action").getNodeValue());

        return (NodeList) xPath.compile("//html/body/form/input").evaluate(doc, XPathConstants.NODESET);
    }

    protected Map<String, String> fragmentToMap(String fragment) {
        return Arrays.stream(fragment.split("&")).map(s -> s.split("="))
                .collect(Collectors.toMap(s -> s[0], s -> s[1]));
    }

    protected Map<String, String> queryParamsToMap(String url) {
        if (!url.contains("?")) {
            return emptyMap();
        }
        String queryPart = url.substring(url.indexOf("?") + 1);
        return fragmentToMap(queryPart);
    }

    protected void expireAccessToken(String token) throws ParseException {
        doExpireToken(token, AccessToken.class);
    }

    protected void expireRefreshToken(String token) throws ParseException {
        doExpireToken(token, RefreshToken.class);
    }

    protected void expireAuthorizationCode(String code) {
        doExpireWithFindProperty(code, AuthorizationCode.class, "code");
    }

    private <T> void doExpireToken(String token, Class<T> clazz) throws ParseException {
        String jwtId = SignedJWT.parse(token).getJWTClaimsSet().getJWTID();
        doExpireWithFindProperty(jwtId, clazz, "jwtId");
    }

    private <T> void doExpireWithFindProperty(String token, Class<T> clazz, String property) {
        Object o = mongoTemplate.find(Query.query(Criteria.where(property).is(token)), clazz).get(0);
        Date expiresIn = Date.from(LocalDateTime.now().minusYears(1L).atZone(ZoneId.systemDefault()).toInstant());
        ReflectionTestUtils.setField(o, "expiresIn", expiresIn);
        mongoTemplate.save(o);
    }
}
