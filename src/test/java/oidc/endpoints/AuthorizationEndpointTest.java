package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseMode;
import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import oidc.model.AuthorizationCode;
import oidc.model.OpenIDClient;
import oidc.model.User;
import oidc.model.UserConsent;
import oidc.secure.SignedJWTTest;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.HttpStatus;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.restassured.RestAssured.given;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AuthorizationEndpointTest extends AbstractIntegrationTest implements SignedJWTTest {

    @Test
    public void authorize() throws IOException {
        String code = doAuthorize();
        assertEquals(12, code.length());
    }

    @Test
    public void authorizeFormPost() throws IOException, ParserConfigurationException, SAXException, XPathExpressionException {
        Response response = doAuthorize("mock-sp", "code", ResponseMode.FORM_POST.getValue(), null, null);
        assertEquals(200, response.getStatusCode());

        NodeList nodeList = getNodeListFromFormPost(response);
        assertEquals("example", nodeList.item(1).getAttributes().getNamedItem("value").getNodeValue());

        String code = nodeList.item(0).getAttributes().getNamedItem("value").getNodeValue();
        assertEquals(12, code.length());

        Map<String, Object> tokenResponse = doToken(code);
        assertTrue(tokenResponse.containsKey("id_token"));
        assertTrue(tokenResponse.containsKey("access_token"));
        assertTrue(tokenResponse.containsKey("refresh_token"));
    }

    @Test
    public void authorizeFragment() throws IOException {
        Response response = doAuthorize("mock-sp", "code", ResponseMode.FRAGMENT.getValue(), null, null);
        String url = response.getHeader("Location");
        String fragment = url.substring(url.indexOf("#") + 1);

        Map<String, String> fragmentParameters = fragmentToMap(fragment);
        String code = fragmentParameters.get("code");

        assertEquals(12, code.length());

        Map<String, Object> tokenResponse = doToken(code);
        assertTrue(tokenResponse.containsKey("id_token"));
        assertTrue(tokenResponse.containsKey("access_token"));
        assertTrue(tokenResponse.containsKey("refresh_token"));
    }


    @Test
    public void oauth2NonOidcCodeFlow() throws IOException {
        String code = doAuthorizeWithScopes("mock-sp", "code", "code", "groups");
        assertEquals(12, code.length());
        Map<String, Object> tokenResponse = doToken(code);
        assertFalse(tokenResponse.containsKey("id_token"));
    }

    @Test
    public void authorizeWithNoImplicitGrant() throws IOException {
        Response response = doAuthorizeWithClaimsAndScopes("mock-rp", "token", "fragment", "nonce", null, Collections.emptyList(), "groups", "state");
        Map<String, Object> result = response.as(mapTypeRef);
        assertEquals("Grant types [authorization_code] does not allow for implicit / hybrid flow", result.get("message"));
        assertEquals(401, result.get("status"));
    }

    @Test
    public void authorizeWithNoAuthorizationCodeGrant() throws IOException {
        Response response = doAuthorizeWithClaimsAndScopes("resource-server-playground-client", "code", "code", "nonce", null, Collections.emptyList(), "openid", "state");
        Map<String, Object> result = response.as(mapTypeRef);
        assertEquals("Grant types [client_credentials] does not allow for authorization code flow", result.get("message"));
        assertEquals(401, result.get("status"));
    }

    @Test
    public void authorizeCodeFlowWithNonce() throws IOException, BadJOSEException, ParseException, JOSEException {
        Response response = doAuthorize("mock-sp", "code", "code", "nonce", null);
        String code = getCode(response);

        Map<String, Object> tokenResponse = doToken(code);
        String idToken = (String) tokenResponse.get("id_token");

        JWTClaimsSet claimsSet = processToken(idToken, port);
        assertEquals("nonce", claimsSet.getClaim("nonce"));
        assertNotNull(claimsSet.getClaim("auth_time"));
    }

    @Test
    public void oauth2NonOidcImplicitFlow() throws IOException {
        Response response = doAuthorizeWithClaimsAndScopes("mock-sp", "token",
                null, null, null, null, "groups", "example");
        String url = response.getHeader("Location");
        String fragment = url.substring(url.indexOf("#") + 1);
        Map<String, String> fragmentParameters = fragmentToMap(fragment);
        assertFalse(fragmentParameters.containsKey("id_token"));
    }

    @Test
    public void noScopeNoState() throws IOException {
        String code = getCode(doAuthorizeWithClaimsAndScopes("mock-sp", "code",
                null, null, null, null, null, null));
        assertEquals(12, code.length());
        Map<String, Object> tokenResponse = doToken(code);
        assertFalse(tokenResponse.containsKey("id_token"));
    }

    @Test
    public void validationMissingParameter() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("redirect_uri", "http%3A%2F%2Flocalhost%3A8080");

        given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize")
                .then()
                .statusCode(302)
                .body(containsString("Missing \\\"client_id\\\" parameter"));
    }

    @Test
    public void validationScope() throws UnsupportedEncodingException {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid nopes");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", "mock-sp");
        queryParams.put("redirect_uri", URLEncoder.encode("http://localhost:3006/redirect", "UTF-8"));

        given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize")
                .then()
                .statusCode(302)
                .body(containsString("not allowed"));
    }

    @Test
    public void validationScopeFormPost() throws UnsupportedEncodingException {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid nopes");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", "mock-sp");
        queryParams.put("response_mode", "form_post");
        queryParams.put("state", "example");
        queryParams.put("redirect_uri", URLEncoder.encode("http://localhost:3006/redirect", "UTF-8"));

        given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize")
                .then()
                .statusCode(401)
                .body(containsString("example"))
                .body(containsString("not allowed"));
    }

    @Test
    public void validationRedirectURI() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", "mock-sp");
        queryParams.put("redirect_uri", "http://nope");

        Map<String, Object> body = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize")
                .as(mapTypeRef);
        assertEquals("Client mock-sp with registered redirect URI's " +
                        "[http://localhost:3006/redirect, http://localhost:3006/oidc/api/redirect] " +
                        "requested authorization with redirectURI http://nope",
                body.get("message"));
    }

    @Test
    public void implicitFlowFragment() throws IOException, BadJOSEException, ParseException, JOSEException {
        Response response = doAuthorizeWithClaims("mock-sp", "id_token token",
                null, "nonce", null, Arrays.asList("email", "nickname"));
        String url = response.getHeader("Location");
        String fragment = url.substring(url.indexOf("#") + 1);
        Map<String, String> fragmentParameters = fragmentToMap(fragment);
        JWTClaimsSet claimsSet = assertImplicitFlowResponse(fragmentParameters);

        assertEquals("john.doe@example.org", claimsSet.getClaim("email"));
        assertEquals("Johhny", claimsSet.getClaim("nickname"));
    }

    @Test
    public void hybridFlowFragment() throws IOException, BadJOSEException, ParseException, JOSEException {
        Response response = doAuthorize("mock-sp", "code id_token token", null, "nonce", null);
        String url = response.getHeader("Location");
        String fragment = url.substring(url.indexOf("#") + 1);
        Map<String, String> fragmentParameters = fragmentToMap(fragment);
        String code = fragmentParameters.get("code");

        AuthorizationCode authorizationCode = mongoTemplate.findOne(Query.query(Criteria.where("code").is(code)), AuthorizationCode.class);
        User user = mongoTemplate.findOne(Query.query(Criteria.where("sub").is(authorizationCode.getSub())), User.class);
        assertNotNull(user);

        String accessToken = fragmentParameters.get("accessToken");
        JWTClaimsSet claimsSet = assertImplicitFlowResponse(fragmentParameters);

        Map<String, Object> tokenResponse = doToken(code);

        List<User> users = mongoTemplate.find(Query.query(Criteria.where("sub").is(authorizationCode.getSub())), User.class);
        assertEquals(0, users.size());

        String newAccessToken = (String) tokenResponse.get("accessToken");
        assertEquals(accessToken, newAccessToken);

        String idToken = (String) tokenResponse.get("id_token");
        JWTClaimsSet newClaimsSet = processToken(idToken, port);

        assertEquals(claimsSet.getAudience(), newClaimsSet.getAudience());
        assertEquals(claimsSet.getSubject(), newClaimsSet.getSubject());
        assertEquals(claimsSet.getIssuer(), newClaimsSet.getIssuer());
    }

    @Test
    public void implicitFlowQuery() throws IOException, BadJOSEException, ParseException, JOSEException {
        Response response = doAuthorize("mock-sp", "id_token token", ResponseMode.QUERY.getValue(), "nonce", null);
        String url = response.getHeader("Location");
        Map<String, String> queryParameters = UriComponentsBuilder.fromUriString(url).build().getQueryParams().toSingleValueMap();
        assertImplicitFlowResponse(queryParameters);
    }

    private JWTClaimsSet assertImplicitFlowResponse(Map<String, ? extends Object> parameters) throws ParseException, MalformedURLException, BadJOSEException, JOSEException {
        String idToken = (String) parameters.get("id_token");
        JWTClaimsSet claimsSet = processToken(idToken, port);
        assertEquals("nonce", claimsSet.getClaim("nonce"));
        assertNotNull(claimsSet.getClaim("at_hash"));
        return claimsSet;
    }

    @Test
    public void implicitFlowFormPost() throws IOException, BadJOSEException, ParseException, JOSEException, ParserConfigurationException, SAXException, XPathExpressionException {
        Response response = doAuthorize("mock-sp", "id_token token", ResponseMode.FORM_POST.getValue(), "nonce", null);
        NodeList nodeList = getNodeListFromFormPost(response);
        assertEquals("example", nodeList.item(2).getAttributes().getNamedItem("value").getNodeValue());

        String idToken = nodeList.item(1).getAttributes().getNamedItem("value").getNodeValue();
        JWTClaimsSet claimsSet = processToken(idToken, port);
        assertEquals("nonce", claimsSet.getClaim("nonce"));
        assertNotNull(claimsSet.getClaim("at_hash"));
    }

    @Test
    public void signedJwtAuthorization() throws Exception {
        OpenIDClient client = openIDClient("mock-sp");
        String cert = readFile("keys/certificate.crt");
        String keyID = getCertificateKeyIDFromCertificate(cert);

        SignedJWT signedJWT = signedJWT(client.getClientId(), keyID, client.getRedirectUrls().get(0));
        Response response = doAuthorizeWithJWTRequest("mock-sp", "code", null, signedJWT, null);

        String location = response.getHeader("Location");
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(location);
        MultiValueMap<String, String> queryParams = builder.build().getQueryParams();
        String state = queryParams.getFirst("state");
        assertEquals("new", state);

        String code = queryParams.getFirst("code");
        Map<String, Object> result = doToken(code);

        String idToken = (String) result.get("id_token");

        JWTClaimsSet claimsSet = processToken(idToken, port);
        assertEquals("123456", claimsSet.getClaim("nonce"));
        assertEquals("john.doe@example.org", claimsSet.getClaim("email"));
        assertEquals("http://test.surfconext.nl/assurance/loa1", claimsSet.getClaim("acr"));

    }

    @Test
    @Ignore
    public void consent() throws IOException {
        doConsent();
        //consent only once
        String code = doAuthorizeWithScopes("playground_client", "code", ResponseMode.QUERY.getValue(), "openid");
        Map<String, Object> body = doToken(code, "playground_client", "secret", GrantType.AUTHORIZATION_CODE);

        assertTrue(body.containsKey("access_token"));

        //consent again if hash changes
        UserConsent userConsent = mongoTemplate.findAll(UserConsent.class).get(0).updateHash(new User("nope", "unspecifiedNameId", "authenticatingAuthority", "clientId",
                Collections.emptyMap(), Collections.emptyList()), Collections.singletonList("openid"));
        mongoTemplate.save(userConsent);
        doConsent();

        userConsent = mongoTemplate.findAll(UserConsent.class).get(0);
        assertEquals("[openid]", userConsent.getScopes().toString());
    }

    private void doConsent() throws IOException {
        Response response = doAuthorize("playground_client", "code", ResponseMode.QUERY.getValue(), "nonce", null);
        String html = response.getBody().asString();
        assertTrue(html.contains("<form method=\"post\" action=\"/oidc/consent\">"));

        Map<String, String> formParams = new HashMap<>();
        Matcher matcher = Pattern.compile("<input type=\"hidden\" name=\"(.+?)\"/>", Pattern.DOTALL).matcher(html);
        while (matcher.find()) {
            String group = matcher.group(1);
            formParams.put(group.substring(0, group.indexOf("\"")), group.substring(group.lastIndexOf("\"") + 1));
        }

        response = given().redirects().follow(false)
                .when()
                .formParams(formParams)
                .post("oidc/consent");
        assertEquals(302, response.getStatusCode());

        String code = getCode(response);
        Map<String, Object> body = doToken(code, "playground_client", "secret", GrantType.AUTHORIZATION_CODE);
        assertTrue(body.containsKey("access_token"));
    }


}