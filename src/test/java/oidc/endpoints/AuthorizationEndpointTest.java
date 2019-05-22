package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ResponseMode;
import io.restassured.response.Response;
import oidc.AbstractIntegrationTest;
import oidc.OidcEndpointTest;
import org.junit.Ignore;
import org.junit.Test;
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
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

public class AuthorizationEndpointTest extends AbstractIntegrationTest implements OidcEndpointTest {

    @Test
    public void authorize() throws UnsupportedEncodingException {
        String code = doAuthorize();
        assertEquals(12, code.length());
    }

    @Test
    public void oauth2NonOidcCodeFlow() throws UnsupportedEncodingException {
        String code = doAuthorizeWithScopes("http@//mock-sp", "code", "code", "groups");
        assertEquals(12, code.length());
        Map<String, Object> tokenResponse = doToken(code);
        assertFalse(tokenResponse.containsKey("id_token"));
    }

    @Test
    @Ignore
    public void authorizeCodeFlowWithNonce() throws UnsupportedEncodingException, MalformedURLException, BadJOSEException, ParseException, JOSEException {
        Response response = doAuthorize("http@//mock-sp", "code", "code", "nonce", null);
        String code = getCode(response);

        Map<String, Object> tokenResponse = doToken(code);
        String idToken = (String) tokenResponse.get("id_token");
        // TODO implement storing the nonce in the AuthorizationCode
        JWTClaimsSet claimsSet = processToken(idToken, port);
        assertEquals("nonce", claimsSet.getClaim("nonce"));
    }

    @Test
    public void oauth2NonOidcImplicitFlow() throws UnsupportedEncodingException {
        Response response = doAuthorizeWithClaimsAndScopes("http@//mock-sp", "token",
                null, null, null, null, "groups", "example");
        String url = response.getHeader("Location");
        String fragment = url.substring(url.indexOf("#") + 1);
        Map<String, String> fragmentParameters = Arrays.stream(fragment.split("&")).map(s -> s.split("=")).collect(Collectors.toMap(s -> s[0], s -> s[1]));
        assertFalse(fragmentParameters.containsKey("id_token"));
    }

    @Test
    public void noScopeNoState() throws UnsupportedEncodingException {
        String code = getCode(doAuthorizeWithClaimsAndScopes("http@//mock-sp", "code",
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
                .header("Location", "http://localhost:8080?error=invalid_request&error_description=Missing%20%22client_id%22%20parameter&state")
                .body(containsString("Missing \\\"client_id\\\" parameter"));
    }

    @Test
    public void validationScope() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid nope");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", "http@//mock-sp");
        queryParams.put("redirect_uri", "http%3A%2F%2Flocalhost%3A8080");

        given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize")
                .then()
                .statusCode(302)
                .header("Location",
                        "http://localhost:8080?error=invalid_request&error_description=Scope(s)%20[nope]%20are%20not%20allowed%20for%20http@//mock-sp.%20Allowed%20scopes:%20[openid,%20groups,%20profile,%20email,%20address,%20phone]&state")
                .body(containsString("not allowed"));
    }

    @Test
    public void validationRedirectURI() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("scope", "openid");
        queryParams.put("response_type", "code");
        queryParams.put("client_id", "http@//mock-sp");
        queryParams.put("redirect_uri", "http://nope");

        Map<String, Object> body = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize")
                .as(mapTypeRef);
        assertEquals("Client http@//mock-sp with registered redirect URI's " +
                        "[http://localhost:8091/redirect, http://localhost:8080] requested " +
                        "authorization with redirectURI http://nope",
                body.get("message"));
    }

    @Test
    public void implicitFlowFragment() throws MalformedURLException, BadJOSEException, ParseException, JOSEException, UnsupportedEncodingException {
        Response response = doAuthorizeWithClaims("http@//mock-sp", "id_token token",
                null, "nonce", null, Arrays.asList("email", "nickname"));
        String url = response.getHeader("Location");
        String fragment = url.substring(url.indexOf("#") + 1);
        Map<String, String> fragmentParameters = Arrays.stream(fragment.split("&")).map(s -> s.split("=")).collect(Collectors.toMap(s -> s[0], s -> s[1]));
        JWTClaimsSet claimsSet = assertImplicitFlowResponse(fragmentParameters);

        assertEquals("john.doe@example.org", claimsSet.getClaim("email"));
        assertEquals("Johhny", claimsSet.getClaim("nickname"));
    }

    @Test
    public void hybridFlowFragment() throws MalformedURLException, BadJOSEException, ParseException, JOSEException, UnsupportedEncodingException {
        Response response = doAuthorize("http@//mock-sp", "code id_token token", null, "nonce", null);
        String url = response.getHeader("Location");
        String fragment = url.substring(url.indexOf("#") + 1);
        Map<String, String> fragmentParameters = Arrays.stream(fragment.split("&")).map(s -> s.split("=")).collect(Collectors.toMap(s -> s[0], s -> s[1]));
        String code = fragmentParameters.get("code");
        String accessToken = fragmentParameters.get("accessToken");
        JWTClaimsSet claimsSet = assertImplicitFlowResponse(fragmentParameters);

        Map<String, Object> tokenResponse = doToken(code);
        String newAccessToken = (String) tokenResponse.get("accessToken");
        assertEquals(accessToken, newAccessToken);

        String idToken = (String) tokenResponse.get("id_token");
        JWTClaimsSet newClaimsSet = processToken(idToken, port);

        assertEquals(claimsSet.getAudience(), newClaimsSet.getAudience());
        assertEquals(claimsSet.getSubject(), newClaimsSet.getSubject());
        assertEquals(claimsSet.getIssuer(), newClaimsSet.getIssuer());
    }

    @Test
    public void implicitFlowQuery() throws MalformedURLException, BadJOSEException, ParseException, JOSEException, UnsupportedEncodingException {
        Response response = doAuthorize("http@//mock-sp", "id_token token", ResponseMode.QUERY.getValue(), "nonce", null);
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
        Response response = doAuthorize("http@//mock-sp", "id_token token", ResponseMode.FORM_POST.getValue(), "nonce", null);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(new ByteArrayInputStream(response.asByteArray()));
        XPath xPath = XPathFactory.newInstance().newXPath();

        Node node = (Node) xPath.compile("//html/body/form").evaluate(doc, XPathConstants.NODE);
        assertEquals("http://localhost:8080", node.getAttributes().getNamedItem("action").getNodeValue());

        NodeList nodeList = (NodeList) xPath.compile("//html/body/form/input").evaluate(doc, XPathConstants.NODESET);
        assertEquals("example", nodeList.item(0).getAttributes().getNamedItem("value").getNodeValue());

        String idToken = nodeList.item(2).getAttributes().getNamedItem("value").getNodeValue();
        JWTClaimsSet claimsSet = processToken(idToken, port);
        assertEquals("nonce", claimsSet.getClaim("nonce"));
        assertNotNull(claimsSet.getClaim("at_hash"));
    }
}