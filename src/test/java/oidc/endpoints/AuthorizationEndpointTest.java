package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseMode;
import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import oidc.model.AuthorizationCode;
import oidc.model.OpenIDClient;
import oidc.model.User;
import oidc.secure.SignedJWTTest;
import org.junit.Test;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
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
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.restassured.RestAssured.given;
import static java.nio.charset.Charset.defaultCharset;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.*;

public class AuthorizationEndpointTest extends AbstractIntegrationTest implements SignedJWTTest {

    @Test
    public void authorizeFormPost() throws IOException, ParserConfigurationException, SAXException, XPathExpressionException {
        Response response = doAuthorize("mock-sp", "code", ResponseMode.FORM_POST.getValue(), null, null);
        assertEquals(200, response.getStatusCode());

        NodeList nodeList = getNodeListFromFormPost(response);
        assertEquals("example", nodeList.item(1).getAttributes().getNamedItem("value").getNodeValue());

        String code = nodeList.item(0).getAttributes().getNamedItem("value").getNodeValue();

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

        Map<String, Object> tokenResponse = doToken(code);
        assertTrue(tokenResponse.containsKey("id_token"));
        assertTrue(tokenResponse.containsKey("access_token"));
        assertTrue(tokenResponse.containsKey("refresh_token"));
    }


    @Test
    public void oauth2NonOidcCodeFlow() throws IOException {
        String code = doAuthorizeWithScopes("mock-sp", "code", "code", "groups");
        Map<String, Object> tokenResponse = doToken(code);
        assertFalse(tokenResponse.containsKey("id_token"));
    }

    @Test
    public void authorizeWithNoImplicitGrant() throws IOException {
        Response response = doAuthorizeWithClaimsAndScopes("mock-rp", "token id_token", "fragment", "nonce", null, Collections.emptyList(), "openid", "state");
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
        String state = "https%3A%2F%2Fexample.com";
        Response response = doAuthorizeWithClaimsAndScopes("mock-sp", "token",
                null, null, null, null, "groups", state);
        String url = response.getHeader("Location");
        String fragment = url.substring(url.indexOf("#") + 1);
        Map<String, String> fragmentParameters = fragmentToMap(fragment);
        assertFalse(fragmentParameters.containsKey("id_token"));
        assertEquals(state, fragmentParameters.get("state"));
    }

    @Test
    public void oauth2NonOidcImplicitFlowStateDecodeDisabled() throws IOException {
        String state = "https%3A%2F%2Fexample.com";
        Response response = doAuthorizeWithClaimsAndScopes("student.mobility.rp.localhost", "token",
                null, null, null, null, "groups", state);
        String url = response.getHeader("Location");
        String fragment = url.substring(url.indexOf("#") + 1);
        Map<String, String> fragmentParameters = fragmentToMap(fragment);
        assertFalse(fragmentParameters.containsKey("id_token"));
        assertEquals(state, fragmentParameters.get("state"));
    }


    @Test
    public void noScopeNoState() throws IOException {
        String code = getCode(doAuthorizeWithClaimsAndScopes("mock-sp", "code",
                null, null, null, null, null, null));
        Map<String, Object> tokenResponse = doToken(code);
        assertFalse(tokenResponse.containsKey("id_token"));
    }

    @Test
    public void queryParamState() throws IOException {
        String state = "https://example.com";
        Response response = doAuthorizeWithClaimsAndScopes("mock-sp", "code",
                null, null, null, null, null, state);
        String location = response.getHeader("Location");
        Map<String, String> queryParams = super.queryParamsToMap(location);
        String stateReturned = queryParams.get("state");
        assertEquals(state, URLDecoder.decode(stateReturned, defaultCharset()));
    }

    @Test
    public void queryParamStateParameterDecodingDisabled() throws IOException {
        String state = "https://example.com";
        Response response = doAuthorizeWithClaimsAndScopes("mock-sp", "code",
                null, null, null, null, null, state);
        String location = response.getHeader("Location");
        Map<String, String> queryParams = super.queryParamsToMap(location);
        String stateReturned = queryParams.get("state");
        assertEquals(state, URLDecoder.decode(stateReturned, defaultCharset()));
    }

    @Test
    public void queryParamStateDecodingDefault() throws IOException {
        String state = "https%3A%2F%2Fexample.com";
        Response response = doAuthorizeWithClaimsAndScopes("student.mobility.rp.localhost", "code",
                null, null, null, null, null, state);
        String location = response.getHeader("Location");
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(location);
        String returnedState = builder.build().getQueryParams().getFirst("state");
        assertEquals(state, returnedState);
    }

    @Test
    public void queryParamStateDecodingDisclaimer() throws IOException {
        String state = "https://example.com";
        Response response = doAuthorizeWithClaimsAndScopes("student.mobility.rp.localhost", "code",
                null, null, null, null, null, state);
        String location = response.getHeader("Location");
        Map<String, String> queryParamsToMap = super.queryParamsToMap(location);
        assertEquals(queryParamsToMap.get("state"), "https%3A%2F%2Fexample.com");
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
    public void noResponseType() throws UnsupportedEncodingException {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid");
        queryParams.put("client_id", "mock-sp");
        queryParams.put("redirect_uri", URLEncoder.encode("http://localhost:3006/redirect", "UTF-8"));

        Response response = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize");
        assertEquals(302, response.getStatusCode());
        String location = response.getHeader("Location");
        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(location).build().getQueryParams();
        assertEquals(params.getFirst("error"), "invalid_request");

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
                .body(containsString("not+allowed"));
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
        String state = "https%3A%2F%2Fexample.com";
        Response response = doAuthorizeWithClaimsAndScopes("mock-sp",
                "code id_token token", null, "nonce", null,
                Collections.emptyList(),"openid", state);
        String url = response.getHeader("Location");
        String fragment = url.substring(url.indexOf("#") + 1);
        Map<String, String> fragmentParameters = fragmentToMap(fragment);
        String code = fragmentParameters.get("code");
        assertEquals(URLEncoder.encode("https://example.com", defaultCharset()), fragmentParameters.get("state"));

        AuthorizationCode authorizationCode = mongoTemplate.findOne(Query.query(Criteria.where("code").is(code)), AuthorizationCode.class);
        User user = mongoTemplate.findOne(Query.query(Criteria.where("sub").is(authorizationCode.getSub())), User.class);
        assertNotNull(user);

        String accessToken = fragmentParameters.get("access_token");
        JWTClaimsSet claimsSet = assertImplicitFlowResponse(fragmentParameters);

        Map<String, Object> tokenResponse = doToken(code);

        List<User> users = mongoTemplate.find(Query.query(Criteria.where("sub").is(authorizationCode.getSub())), User.class);
        assertEquals(0, users.size());

        String newAccessToken = (String) tokenResponse.get("access_token");
        /*
         * If an Access Token is returned from both the Authorization Endpoint and from the Token Endpoint, which is
         * the case for the response_type values code token and code id_token token, their values MAY be the same or
         * they MAY be different. Note that different Access Tokens might be returned be due to the different
         * security characteristics of the two endpoints and the lifetimes and the access to resources granted
         * by them might also be different.
         */
        assertNotEquals(accessToken, newAccessToken);

        String idToken = (String) tokenResponse.get("id_token");
        JWTClaimsSet newClaimsSet = processToken(idToken, port);

        assertEquals(claimsSet.getAudience(), newClaimsSet.getAudience());
        assertEquals(claimsSet.getSubject(), newClaimsSet.getSubject());
        assertEquals(claimsSet.getIssuer(), newClaimsSet.getIssuer());
    }

    @Test
    public void implicitFlowQuery() throws IOException, BadJOSEException, ParseException, JOSEException {
        String state = "https%3A%2F%2Fexample.com";
        Response response = doAuthorizeWithClaimsAndScopes("mock-sp",
                "id_token token", ResponseMode.QUERY.getValue(), "nonce", null,
                Collections.emptyList(), "openid", state);
        String url = response.getHeader("Location");
        Map<String, String> queryParameters = UriComponentsBuilder.fromUriString(url).build().getQueryParams().toSingleValueMap();
        assertEquals(state, queryParameters.get("state"));
        assertImplicitFlowResponse(queryParameters);
    }

    @Test
    public void implicitFlowQueryStateDecodingDisabled() throws IOException, BadJOSEException, ParseException, JOSEException {
        String state = "https%3A%2F%2Fexample.com";
        Response response = doAuthorizeWithClaimsAndScopes("student.mobility.rp.localhost", "id_token token", ResponseMode.QUERY.getValue(), "nonce", null,
                Collections.emptyList(), "openid", state);
        String url = response.getHeader("Location");
        Map<String, String> queryParameters = UriComponentsBuilder.fromUriString(url).build().getQueryParams().toSingleValueMap();
        assertEquals(state, queryParameters.get("state"));
        assertImplicitFlowResponse(queryParameters);
    }

    @Test
    public void implicitFlowQueryStateDecodingDisabledNoClientEncoding() throws IOException, BadJOSEException, ParseException, JOSEException {
        String state = "https://example.com";
        Response response = doAuthorizeWithClaimsAndScopes("student.mobility.rp.localhost", "id_token token", ResponseMode.QUERY.getValue(), "nonce", null,
                Collections.emptyList(), "openid", state);
        String url = response.getHeader("Location");
        Map<String, String> queryParams = super.queryParamsToMap(url);
        assertEquals(URLEncoder.encode(state, defaultCharset()), queryParams.get("state"));
        assertImplicitFlowResponse(queryParams);
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
        assertEquals("loa1 loa2 loa3", claimsSet.getClaim("acr"));
    }

    @Test
    public void unSignedJwtAuthorization() throws Exception {
        OpenIDClient client = openIDClient("mock-sp");
        PlainJWT plainJWT = plainJWT(client.getClientId(), client.getRedirectUrls().get(0));
        String location = doAuthorizeWithJWTRequest("mock-sp", "code", null, plainJWT, null).getHeader("Location");
        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(location).build().getQueryParams();
        assertEquals(params.getFirst("error"), "request_not_supported");
    }


    @Test
    public void consent() throws IOException {
        Response response = doAuthorizeWithClaimsAndScopes("playground_client", "code", ResponseMode.QUERY.getValue(), "nonce", null,
                Collections.emptyList(), "https://voot.surfconext.nl/groups groups", "state");
        String html = response.getBody().asString();
        assertTrue(html.contains("<form method=\"post\" action=\"/oidc/consent\">"));

        Map<String, String> formParams = new HashMap<>();
        Matcher matcher = Pattern.compile("<input type=\"hidden\" name=\"(.+?)\"/>", Pattern.DOTALL).matcher(html);
        while (matcher.find()) {
            String group = matcher.group(1);
            formParams.put(group.substring(0, group.indexOf("\"")), group.substring(group.lastIndexOf("\"") + 1));
        }
        assertEquals("state", formParams.get("state"));

        response = given().redirects().follow(false)
                .when()
                .formParams(formParams)
                .post("oidc/consent");
        assertEquals(302, response.getStatusCode());
        String location = response.getHeader("Location");
        assertTrue(location.contains("state=state"));

        String code = getCode(response);
        Map<String, Object> body = doToken(code, "playground_client", "secret", GrantType.AUTHORIZATION_CODE);
        assertTrue(body.containsKey("access_token"));
    }

    @Test
    public void authorizeUnknownClient() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", "nope");
        given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize")
                .then()
                .statusCode(401)
                .body("message", equalTo("ClientID nope or secret is not correct"));
    }
}