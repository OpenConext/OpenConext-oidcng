package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import oidc.AbstractIntegrationTest;
import oidc.model.AccessToken;
import oidc.model.RefreshToken;
import oidc.model.User;
import oidc.secure.TokenGenerator;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.auth.JWTAuthentication.CLIENT_ASSERTION_TYPE;
import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

@SuppressWarnings("unchecked")
public class TokenEndpointTest extends AbstractIntegrationTest {

    @Autowired
    private TokenGenerator tokenGenerator;

    @Autowired
    private @Value("${spring.security.saml2.service-provider.entity-id}")
    String issuer;

    @Test
    public void token() throws MalformedURLException, ParseException, JOSEException, BadJOSEException, UnsupportedEncodingException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);

        String refreshToken = (String) body.get("refresh_token");
        assertNotNull(refreshToken);

        String accessToken = (String) body.get("access_token");
        assertNotNull(accessToken);
        JWTClaimsSet accessTokenClaimsSet = processToken(accessToken, port);
        List<String> audience = accessTokenClaimsSet.getAudience();
        assertEquals(Arrays.asList("mock-sp", "resource-server"), audience);

        String idToken = (String) body.get("id_token");
        verifySignedJWT(idToken, port);
        JWTClaimsSet claimsSet = processToken(idToken, port);

        assertEquals(Collections.singletonList("mock-sp"), claimsSet.getAudience());
    }

    @Test
    public void oauth2NonOidcFlow() throws UnsupportedEncodingException {
        String code = doAuthorizeWithScopes("mock-sp", "code", "code", "groups");
        Map<String, Object> body = doToken(code);

        String accessToken = (String) body.get("access_token");
        assertNotNull(accessToken);

        String idToken = (String) body.get("id_token");
        assertNull(idToken);
    }

    @Test
    public void invalidToken() {
        Map<String, Object> body = doToken("nope");

        assertEquals(body.get("status"), 404);
        assertEquals(body.get("error"), "Not Found");
    }

    @Test
    public void tokenWithClaims() throws MalformedURLException, ParseException, JOSEException, BadJOSEException, UnsupportedEncodingException {
        Response response = doAuthorizeWithClaims("mock-sp", "code", null, null, null, Arrays.asList("email", "nickname"));
        String code = getCode(response);
        Map<String, Object> body = doToken(code);

        String idToken = (String) body.get("id_token");
        JWTClaimsSet claimsSet = processToken(idToken, port);

        assertEquals("john.doe@example.org", claimsSet.getClaim("email"));
        assertEquals("Johhny", claimsSet.getClaim("nickname"));
    }

    @Test
    public void clientCredentials() throws ParseException {
        Map<String, Object> body = doToken(null, "mock-sp", "secret", GrantType.CLIENT_CREDENTIALS);
        String idToken = (String) body.get("id_token");
        SignedJWT jwt = SignedJWT.parse(idToken);
        JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();

        assertEquals(Collections.singletonList("mock-sp"), claimsSet.getAudience());
    }

    @Test
    public void authorizationCodeExpired() throws UnsupportedEncodingException {
        String code = doAuthorize();
        expireAuthorizationCode(code);
        Map<String, Object> body = doToken(code);
        assertEquals("Authorization code expired", body.get("message"));
    }

    @Test
    public void refreshToken() throws ParseException, JOSEException, MalformedURLException, UnsupportedEncodingException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);

        doRefreshToken(body, "secret");
    }

    @Test
    public void refreshTokenExpired() throws ParseException, JOSEException, MalformedURLException, UnsupportedEncodingException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);
        String refreshToken = (String) body.get("refresh_token");
        expireRefreshToken(refreshToken);

        Map<String, Object> result = doRefreshToken(body, "secret");
        assertEquals("Refresh token expired", result.get("message"));
    }

    @Test
    public void refreshTokenForPublicClient() throws ParseException, JOSEException, MalformedURLException, UnsupportedEncodingException {
        String codeChallenge = StringUtils.leftPad("token", 45, "*");
        Response response = doAuthorize("mock-sp", "code", null, "nonce",
                codeChallenge);
        String code = getCode(response);

        Map<String, Object> body = doToken(code, "mock-sp", null, GrantType.AUTHORIZATION_CODE,
                codeChallenge);

        doRefreshToken(body, null);
    }

    @Test
    public void deviceCodeNotSupported() throws ParseException, JOSEException, MalformedURLException, UnsupportedEncodingException {
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
    public void clientCredentialsInvalidGrant() throws ParseException {
        Map<String, Object> body = doToken(null, "mock-rp", "secret", GrantType.CLIENT_CREDENTIALS);

        assertEquals("Invalid grant: client_credentials", body.get("message"));
    }

    @Test
    public void invalidSecret() {
        Map<String, Object> body = doToken(null, "mock-sp", "nope", GrantType.CLIENT_CREDENTIALS);

        assertEquals("Invalid user / secret", body.get("details"));
    }

    @Test
    public void nonPublicClient() throws UnsupportedEncodingException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code, "mock-rp", null, GrantType.AUTHORIZATION_CODE,
                StringUtils.leftPad("token", 45, "*"));

        assertEquals("Non-public client requires authentication", body.get("details"));
    }

    @Test
    public void clientMismatch() throws UnsupportedEncodingException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code, "mock-rp", "secret", GrantType.AUTHORIZATION_CODE, null);

        assertEquals("Client is not authorized for the authorization code", body.get("details"));
    }

    @Test
    public void codeChallengeMissing() throws UnsupportedEncodingException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code, "mock-sp", null, GrantType.AUTHORIZATION_CODE);

        assertEquals("code_verifier required without client authentication", body.get("message"));
    }

    @Test
    public void codeChallengeInvalid() throws UnsupportedEncodingException {
        Response response = doAuthorize("mock-sp", "code", null, null,
                StringUtils.leftPad("token", 45, "-"));
        String code = getCode(response);
        Map<String, Object> body = doToken(code, "mock-sp", null, GrantType.AUTHORIZATION_CODE,
                StringUtils.leftPad("token", 45, "*"));
        assertEquals("code_verifier does not match code_challenge", body.get("message"));
    }

    @Test
    public void codeChallengeNotInAuthorisationCode() throws UnsupportedEncodingException {
        Response response = doAuthorize("mock-sp", "code", null, null, null);
        String code = getCode(response);
        Map<String, Object> body = doToken(code, "mock-sp", null, GrantType.AUTHORIZATION_CODE,
                StringUtils.leftPad("token", 45, "*"));
        assertEquals("code_verifier present, but no code_challenge in the authorization_code", body.get("message"));
    }

    @Test
    public void redirectMismatch() throws UnsupportedEncodingException {
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
    public void unsupportedClientAuthentication() throws JOSEException, IOException, NoSuchProviderException, NoSuchAlgorithmException {
        String code = doAuthorize();
        String idToken = tokenGenerator.generateIDTokenForTokenEndpoint(Optional.of(user(issuer)), openIDClient(), "nonce", Collections.emptyList());
        Map<String, Object> body = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded")
                .formParam("client_assertion_type", CLIENT_ASSERTION_TYPE)
                .formParam("client_assertion", idToken)
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("code", code)
                .post("oidc/token")
                .as(mapTypeRef);
        assertEquals("Unsupported 'class com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT' findByClientId authentication in token endpoint",
                body.get("message"));
    }

    private User user(String issuer) {
        User user = new User();
        ReflectionTestUtils.setField(user, "sub", issuer);
        return user;
    }
}