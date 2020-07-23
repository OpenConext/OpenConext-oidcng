package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import oidc.AbstractIntegrationTest;
import oidc.model.AccessToken;
import oidc.model.RefreshToken;
import oidc.model.User;
import oidc.secure.SignedJWTTest;
import oidc.secure.TokenGenerator;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.nimbusds.oauth2.sdk.auth.JWTAuthentication.CLIENT_ASSERTION_TYPE;
import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@SuppressWarnings("unchecked")
public class TokenEndpointTest extends AbstractIntegrationTest implements SignedJWTTest {

    @Autowired
    private TokenGenerator tokenGenerator;

    @Autowired
    @Value("${spring.security.saml2.service-provider.entity-id}")
    private String issuer;

    @Test
    public void token() throws IOException, ParseException, JOSEException, BadJOSEException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);

        String refreshToken = (String) body.get("refresh_token");
        assertNotNull(refreshToken);

        String accessToken = (String) body.get("access_token");
        assertNotNull(accessToken);
        JWTClaimsSet accessTokenClaimsSet = processToken(accessToken, port);
        List<String> audience = accessTokenClaimsSet.getAudience();
        assertEquals(Arrays.asList("mock-sp", "resource-server-playground-client"), audience);

        String idToken = (String) body.get("id_token");
        verifySignedJWT(idToken, port);
        JWTClaimsSet claimsSet = processToken(idToken, port);

        assertEquals(Collections.singletonList("mock-sp"), claimsSet.getAudience());
    }

    @Test
    public void tokenTwice() throws IOException {
        String code = doAuthorize();
        String accessToken = (String) doToken(code).get("access_token");

        String accessTokenValue = AccessToken.computeInnerValueFromJWT(accessToken);
        assertEquals(1, mongoTemplate.find(Query.query(Criteria.where("value").is(accessTokenValue)), AccessToken.class).size());

        Map<String, Object> body = doToken(code);
        assertEquals(401, body.get("status"));
        assertEquals("Authorization code already used", body.get("message"));

        assertEquals(0, mongoTemplate.find(Query.query(Criteria.where("value").is(accessTokenValue)), AccessToken.class).size());
    }

    @Test
    public void oauth2NonOidcFlow() throws IOException {
        String code = doAuthorizeWithScopes("mock-sp", "code", "code", "groups");
        Map<String, Object> body = doToken(code);

        String accessToken = (String) body.get("access_token");
        assertNotNull(accessToken);

        String idToken = (String) body.get("id_token");
        assertNull(idToken);
    }

    @Test
    public void invalidToken() throws IOException {
        Map<String, Object> body = doToken("nope");

        assertEquals("invalid_grant", body.get("error"));
    }

    @Test
    public void tokenWithClaims() throws IOException, ParseException, JOSEException, BadJOSEException {
        Response response = doAuthorizeWithClaims("mock-sp", "code", null, null, null, Arrays.asList("email", "nickname"));
        String code = getCode(response);
        Map<String, Object> body = doToken(code);

        String idToken = (String) body.get("id_token");
        JWTClaimsSet claimsSet = processToken(idToken, port);

        assertEquals("john.doe@example.org", claimsSet.getClaim("email"));
        assertEquals("Johhny", claimsSet.getClaim("nickname"));
    }

    @Test
    public void clientCredentials() throws ParseException, IOException {
        Map<String, Object> body = doToken(null, "mock-sp", "secret", GrantType.CLIENT_CREDENTIALS);
        assertEquals(false, body.containsKey("id_token"));
        String accessToken = (String) body.get("access_token");
        SignedJWT signedJWT = SignedJWT.parse(accessToken);
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

        assertEquals("https://org.openconext.oidc.ng", jwtClaimsSet.getIssuer());
        assertEquals("mock-sp", jwtClaimsSet.getSubject());
    }

    @Test
    public void authorizationCodeExpired() throws IOException {
        String code = doAuthorize();
        expireAuthorizationCode(code);
        Map<String, Object> body = doToken(code);
        assertEquals("Authorization code expired", body.get("message"));
    }


    @Test
    public void refreshToken() throws ParseException, JOSEException, IOException, BadJOSEException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);

        Map<String, Object> result = doRefreshToken(body, "secret");
        JWTClaimsSet claimsSet = processToken((String) result.get("id_token"), port);
        assertNotNull(claimsSet.getClaim("auth_time"));
    }

    @Test
    public void refreshTokenExpired() throws ParseException, JOSEException, IOException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);
        String refreshToken = (String) body.get("refresh_token");
        expireRefreshToken(refreshToken);

        Map<String, Object> result = doRefreshToken(body, "secret");
        assertEquals("Refresh token expired", result.get("message"));
    }

    @Test
    public void refreshTokenForPublicClient() throws ParseException, JOSEException, IOException {
        String codeChallenge = StringUtils.leftPad("token", 45, "*");
        Response response = doAuthorize("mock-sp", "code", null, "nonce",
                codeChallenge);
        String code = getCode(response);

        Map<String, Object> body = doToken(code, "mock-sp", null, GrantType.AUTHORIZATION_CODE,
                codeChallenge);

        doRefreshToken(body, null);
    }

    @Test
    public void deviceCodeNotSupported() throws ParseException, JOSEException, IOException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);

        Map<String, Object> result = doTokenWithGrantType(body, "secret", GrantType.DEVICE_CODE, Collections.singletonMap("device_code", "12345"));
        assertEquals("Not supported - yet - authorizationGrant urn:ietf:params:oauth:grant-type:device_code", result.get("message"));
    }

    private Map<String, Object> doRefreshToken(Map<String, Object> body, String secret) throws MalformedURLException, JOSEException, ParseException {
        return doTokenWithGrantType(body, secret, GrantType.REFRESH_TOKEN, Collections.emptyMap());
    }

    private Map<String, Object> doTokenWithGrantType(Map<String, Object> body, String secret, GrantType grantType,
                                                     Map<String, String> additionalParameters) throws MalformedURLException, JOSEException, ParseException {
        String refreshToken = (String) body.get("refresh_token");
        String accessToken = (String) body.get("access_token");
        RequestSpecification header = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded");
        if (!StringUtils.isEmpty(secret)) {
            header = header.auth().preemptive().basic("mock-sp", secret);
        } else {
            header = header.formParam("client_id", "mock-sp");
        }

        Map<String, Object> result = header
                .formParam("grant_type", grantType.getValue())
                .formParam(grantType.getValue(), refreshToken)
                .formParams(additionalParameters)
                .post("oidc/token")
                .as(Map.class);
        if (result.containsKey("error")) {
            return result;
        }
        verifySignedJWT((String) result.get("id_token"), port);

        assertEquals(0, mongoTemplate.find(Query.query(Criteria.where("value").is(accessToken)), AccessToken.class).size());
        assertEquals(0, mongoTemplate.find(Query.query(Criteria.where("value").is(refreshToken)), RefreshToken.class).size());

        assertNotNull(body.get("refresh_token"));
        assertNotNull(body.get("access_token"));
        return result;
    }


    @Test
    public void clientCredentialsInvalidGrant() throws ParseException, IOException {
        Map<String, Object> body = doToken(null, "mock-rp", "secret", GrantType.CLIENT_CREDENTIALS);

        assertEquals("Invalid grant: client_credentials", body.get("message"));
    }

    @Test
    public void invalidSecret() throws IOException {
        Map<String, Object> body = doToken(null, "mock-sp", "nope", GrantType.CLIENT_CREDENTIALS);

        assertEquals("Invalid user / secret", body.get("error_description"));
    }

    @Test
    public void nonPublicClient() throws IOException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code, "mock-rp", null, GrantType.AUTHORIZATION_CODE,
                StringUtils.leftPad("token", 45, "*"));

        assertEquals("Non-public client requires authentication", body.get("error_description"));
    }

    @Test
    public void clientMismatch() throws IOException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code, "mock-rp", "secret", GrantType.AUTHORIZATION_CODE, null);

        assertEquals("Client is not authorized for the authorization code", body.get("error_description"));
    }

    @Test
    public void codeChallengeMissing() throws IOException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code, "mock-sp", null, GrantType.AUTHORIZATION_CODE);

        assertEquals("code_verifier required without client authentication", body.get("message"));
    }

    @Test
    public void codeChallengeInvalid() throws IOException {
        Response response = doAuthorize("mock-sp", "code", null, null,
                StringUtils.leftPad("token", 45, "-"));
        String code = getCode(response);
        Map<String, Object> body = doToken(code, "mock-sp", null, GrantType.AUTHORIZATION_CODE,
                StringUtils.leftPad("token", 45, "*"));
        assertEquals("code_verifier does not match code_challenge", body.get("message"));
    }

    @Test
    public void codeChallengeNotInAuthorisationCode() throws IOException {
        Response response = doAuthorize("mock-sp", "code", null, null, null);
        String code = getCode(response);
        Map<String, Object> body = doToken(code, "mock-sp", null, GrantType.AUTHORIZATION_CODE,
                StringUtils.leftPad("token", 45, "*"));
        assertEquals("code_verifier present, but no code_challenge in the authorization_code", body.get("message"));
    }

    @Test
    public void codeChallengeFlow() throws IOException {
        String verifier = "12345678901234567890123456789012345678901234567890";
        CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, new CodeVerifier(verifier));

        Response response = doAuthorizeWithClaimsAndScopesAndCodeChallengeMethod("mock-sp", "code", null, "nonce",
                codeChallenge.getValue(), Collections.emptyList(), "openid", "state", CodeChallengeMethod.S256.getValue());
        String code = getCode(response);
        Map<String, Object> body = doToken(code, "mock-sp", null, GrantType.AUTHORIZATION_CODE, verifier);
        assertTrue(body.containsKey("id_token"));
    }

    @Test
    public void redirectMismatch() throws IOException {
        String code = doAuthorize();
        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .auth().preemptive()
                .basic("mock-sp", "secret")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("code", code)
                .formParam("redirect_uri", "http://nope")
                .post("oidc/token")
                .as(mapTypeRef);
        assertEquals("Redirects do not match", body.get("message"));
    }

    @Test
    public void missingRedirect() throws IOException {
        String code = doAuthorize();
        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .auth().preemptive()
                .basic("mock-sp", "secret")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("code", code)
                .post("oidc/token")
                .as(mapTypeRef);
        assertEquals("Redirect URI is mandatory if specified in code request", body.get("message"));
    }

    @Test
    public void privateKeyJwtAuthentication() throws IOException, JOSEException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException {
        PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(
                new ClientID("rp-jwt-authentication"),
                URI.create("http://localhost:8080/oidc/token"),
                JWSAlgorithm.RS256,
                privateKey(),
                "does-not-matter", null);
        Map<String, Object> body = doJwtAuthenticationAuthorization(privateKeyJWT);
        assertTrue(body.containsKey("id_token"));
        assertTrue(body.containsKey("access_token"));
    }

    @Test
    public void clientSecretJwtAuthentication() throws IOException, JOSEException {
        Map<String, Object> body = doClientSecretJwtAuthorization("very-long-long-long-long-long-secret");
        assertTrue(body.containsKey("id_token"));
        assertTrue(body.containsKey("access_token"));
    }

    @Test
    public void clientWrongSecretJwtAuthentication() throws IOException, JOSEException {
        Map<String, Object> body = doClientSecretJwtAuthorization("very-long-long-long-long-long-secret-but-invalid");
        assertEquals(403, body.get("status"));
        assertEquals("Invalid user / signature", body.get("error"));
    }

    @Test
    public void clientSecretJwtAuthorizationInvalidAudience() throws IOException, JOSEException {
        ClientSecretJWT clientSecretJWT = clientSecretJWT(
                "rp-jwt-authentication", "http://nope",
                "very-long-long-long-long-long-secret",
                new Date(new Date().getTime() + 5 * 60 * 1000L)
        );
        Map<String, Object> res = doJwtAuthenticationAuthorization(clientSecretJWT);
        assertEquals(400, res.get("status"));
        assertEquals("invalid_grant", res.get("error"));
        assertEquals("Invalid audience", res.get("error_description"));
    }

    @Test
    public void clientSecretJwtAuthorizationExpired() throws IOException, JOSEException {
        ClientSecretJWT clientSecretJWT = clientSecretJWT(
                "rp-jwt-authentication", "http://localhost:8080/oidc/token",
                "very-long-long-long-long-long-secret",
                new Date(new Date().getTime() - 5 * 60 * 1000L)
        );
        Map<String, Object> res = doJwtAuthenticationAuthorization(clientSecretJWT);
        assertEquals(400, res.get("status"));
        assertEquals("invalid_grant", res.get("error"));
        assertEquals("Expired claims", res.get("error_description"));
    }

    private Map<String, Object> doClientSecretJwtAuthorization(String secret) throws IOException, JOSEException {
        ClientSecretJWT clientSecretJWT = new ClientSecretJWT(
                new ClientID("rp-jwt-authentication"),
                URI.create("http://localhost:8080/oidc/token"),
                JWSAlgorithm.HS256,
                new Secret(secret));

        return doJwtAuthenticationAuthorization(clientSecretJWT);
    }

    private Map<String, Object> doJwtAuthenticationAuthorization(JWTAuthentication jwtAuthentication) throws IOException, JOSEException {
        Response response = doAuthorize("rp-jwt-authentication", "code", null, null, null);
        String code = getCode(response);

        return given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("client_assertion_type", CLIENT_ASSERTION_TYPE)
                .formParam("client_assertion", jwtAuthentication.getClientAssertion().serialize())
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("code", code)
                .formParam("redirect_uri", "http://localhost:8091/redirect")
                .post("oidc/token")
                .as(mapTypeRef);
    }

    private User user(String issuer) {
        User user = new User();
        ReflectionTestUtils.setField(user, "sub", issuer);
        return user;
    }

    private ClientSecretJWT clientSecretJWT(String issuer, String tokenEndPoint, String secret, Date expiration) throws JOSEException {
        //Issuer and subject in client JWT assertion must designate the same client identifier
        JWTAssertionDetails jwtAssertionDetails = new JWTAssertionDetails(
                new Issuer(issuer), new Subject(issuer), Audience.create(tokenEndPoint), expiration,
                null, null, null, null);
        SignedJWT signedJWT = JWTAssertionFactory.create(jwtAssertionDetails, JWSAlgorithm.HS256, new Secret(secret));
        return new ClientSecretJWT(signedJWT);
    }
}