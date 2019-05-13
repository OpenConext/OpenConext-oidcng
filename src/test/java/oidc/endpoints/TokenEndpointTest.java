package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import oidc.AbstractIntegrationTest;
import oidc.OidcEndpointTest;
import oidc.model.AccessToken;
import oidc.model.RefreshToken;
import oidc.secure.TokenGenerator;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.auth.JWTAuthentication.CLIENT_ASSERTION_TYPE;
import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@SuppressWarnings("unchecked")
public class TokenEndpointTest extends AbstractIntegrationTest implements OidcEndpointTest {

    private String issuer = "issuer";
    private TokenGenerator tokenGenerator = new TokenGenerator(
            new ClassPathResource("oidc.keystore.jwks.json"),
            issuer,
            "Y3nS5p0bKLI8bR/thxo0CFS3uItJXifjfRymRGOGJhRgij48ttTjPR33ZdAhobHrXd5MJNz4X69wYKvsUMlIfg==");

    public TokenEndpointTest() throws ParseException, JOSEException, IOException {
    }

    @Test
    public void token() throws MalformedURLException, ParseException, JOSEException, BadJOSEException, UnsupportedEncodingException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);

        String refreshToken = (String) body.get("refresh_token");
        assertNotNull(refreshToken);

        String accessToken = (String) body.get("access_token");
        assertNotNull(accessToken);

        String idToken = (String) body.get("id_token");
        verifySignedJWT(idToken, port);
        JWTClaimsSet claimsSet = processToken(idToken, port);

        assertEquals(Collections.singletonList("http@//mock-sp"), claimsSet.getAudience());
    }

    @Test
    public void clientCredentials() throws ParseException {
        Map<String, Object> body = doToken(null, "http@//mock-sp", "secret", GrantType.CLIENT_CREDENTIALS);
        String idToken = (String) body.get("id_token");
        SignedJWT jwt = SignedJWT.parse(idToken);
        JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();

        assertEquals(Collections.singletonList("http@//mock-sp"), claimsSet.getAudience());
    }

    @Test
    public void refreshToken() throws ParseException, JOSEException, MalformedURLException, UnsupportedEncodingException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);

        doRefreshToken(body, "secret");
    }

    @Test
    public void refreshTokenForPublicClient() throws ParseException, JOSEException, MalformedURLException, UnsupportedEncodingException {
        String codeChallenge = StringUtils.leftPad("token", 45, "*");
        Response response = doAuthorize("http@//mock-sp", "code", null, "nonce",
                codeChallenge);
        String code = getCode(response);

        Map<String, Object> body = doToken(code, "http@//mock-sp", null, GrantType.AUTHORIZATION_CODE,
                codeChallenge);

        doRefreshToken(body, null);
    }

    private void doRefreshToken(Map<String, Object> body, String secret) throws MalformedURLException, JOSEException, ParseException {
        String refreshToken = (String) body.get("refresh_token");
        String accessToken = (String) body.get("access_token");
        RequestSpecification header = given()
                .when()
                .header("Content-type", "application/x-www-form-urlencoded");
        if (!StringUtils.isEmpty(secret)) {
            header = header.auth().preemptive().basic("http@//mock-sp", secret);
        } else {
            header = header.formParam("client_id", "http@//mock-sp");
        }
        Map<String, Object> result = header
                .formParam("grant_type", GrantType.REFRESH_TOKEN.getValue())
                .formParam(GrantType.REFRESH_TOKEN.getValue(), refreshToken)
                .post("oidc/token")
                .as(Map.class);
        verifySignedJWT((String) result.get("id_token"), port);

        assertEquals(0, mongoTemplate.find(Query.query(Criteria.where("value").is(accessToken)), AccessToken.class).size());
        assertEquals(0, mongoTemplate.find(Query.query(Criteria.where("value").is(refreshToken)), RefreshToken.class).size());

        assertNotNull(body.get("refresh_token"));
        assertNotNull(body.get("access_token"));
    }


    @Test
    public void clientCredentialsInvalidGrant() throws ParseException {
        Map<String, Object> body = doToken(null, "http@//mock-rp", "secret", GrantType.CLIENT_CREDENTIALS);

        assertEquals("Invalid grant", body.get("message"));
    }

    @Test
    public void invalidSecret() {
        Map<String, Object> body = doToken(null, "http@//mock-sp", "nope", GrantType.CLIENT_CREDENTIALS);

        assertEquals("Invalid user / secret", body.get("details"));
    }

    @Test
    public void nonPublicClient() throws UnsupportedEncodingException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code, "http@//mock-rp", null, GrantType.AUTHORIZATION_CODE,
                StringUtils.leftPad("token", 45, "*"));

        assertEquals("Non-public client requires authentication", body.get("details"));
    }

    @Test
    public void clientMismatch() throws UnsupportedEncodingException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code, "http@//mock-rp", "secret", GrantType.AUTHORIZATION_CODE, null);

        assertEquals("Client is not authorized for the authorization code", body.get("details"));
    }

    @Test
    public void codeChallengeMissing() throws UnsupportedEncodingException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code, "http@//mock-sp", null, GrantType.AUTHORIZATION_CODE);

        assertEquals("code_verifier required without client authentication", body.get("message"));
    }

    @Test
    public void codeChallengeInvalid() throws UnsupportedEncodingException {
        Response response = doAuthorize("http@//mock-sp", "code", null, null,
                StringUtils.leftPad("token", 45, "-"));
        String code = getCode(response);
        Map<String, Object> body = doToken(code, "http@//mock-sp", null, GrantType.AUTHORIZATION_CODE,
                StringUtils.leftPad("token", 45, "*"));
        assertEquals("code_verifier does not match code_challenge", body.get("message"));
    }

    @Test
    public void codeChallengeNotInAuthorisationCode() throws UnsupportedEncodingException {
        Response response = doAuthorize("http@//mock-sp", "code", null, null, null);
        String code = getCode(response);
        Map<String, Object> body = doToken(code, "http@//mock-sp", null, GrantType.AUTHORIZATION_CODE,
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
                .basic("http@//mock-sp", "secret")
                .formParam("grant_type", GrantType.AUTHORIZATION_CODE.getValue())
                .formParam("code", code)
                .formParam("redirect_uri", "http://nope")
                .post("oidc/token")
                .as(mapTypeRef);
        assertEquals("Redirects do not match", body.get("message"));
    }

    @Test
    public void unsupportedClientAuthentication() throws JOSEException, UnsupportedEncodingException {
        String code = doAuthorize();
        String idToken = tokenGenerator.generateIDTokenForTokenEndpoint(Optional.empty(), issuer, Collections.emptyList());
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
}