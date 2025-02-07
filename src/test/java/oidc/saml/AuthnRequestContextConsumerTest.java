package oidc.saml;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import io.restassured.response.Response;
import lombok.SneakyThrows;
import oidc.AbstractIntegrationTest;
import org.junit.Test;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import static io.restassured.RestAssured.given;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.*;

@ActiveProfiles(value = "", inheritProfiles = false)
public class AuthnRequestContextConsumerTest extends AbstractIntegrationTest {

    static {
        OpenSamlInitializationService.initialize();
    }

    @Test
    public void testSaml() throws IOException {
        Map<String, String> queryParams = new HashMap<>();
        String clientId = "mock-sp";
        queryParams.put("scope", "openid");
        queryParams.put("client_id", clientId);
        queryParams.put("response_type", "code");
        queryParams.put("redirect_uri", openIDClient(clientId).getRedirectUrls().get(0));
        Response response = given().redirects().follow(false)
                .when()
                .header("Content-type", "application/json")
                .queryParams(queryParams)
                .get("oidc/authorize");
        Map<String, String> cookies = response.getCookies();

        String location = response.getHeader("Location");
        assertTrue(location.endsWith("/saml2/authenticate?registrationId=oidcng"));

        response = given().redirects().follow(false)
                .cookies(cookies)
                .when()
                .get("saml2/authenticate?registrationId=oidcng");

        String ebLocation = response.getHeader("Location");
        assertTrue(ebLocation.startsWith("https://engine"));

        MultiValueMap<String, String> params = UriComponentsBuilder.fromUriString(ebLocation).build().getQueryParams();
        Arrays.asList("SAMLRequest", "SigAlg", "Signature").forEach(param -> assertTrue(params.containsKey(param)));

        String samlRequest = params.getFirst("SAMLRequest");
        String urlDecoded = URLDecoder.decode(samlRequest, Charset.defaultCharset());
        byte[] base64Decoded = Base64.getDecoder().decode(urlDecoded);
        String xml = inflate(base64Decoded);

        XmlMapper xmlMapper = new XmlMapper();
        Map<String, Object> map = xmlMapper.readValue(xml, Map.class);

        //Ensure all the values are properly set
        assertEquals("http://localhost:8080/login/saml2/sso/oidcng", map.get("AssertionConsumerServiceURL"));
        assertEquals("https://engine.test2.surfconext.nl/authentication/idp/single-sign-on", map.get("Destination"));
        assertEquals("https://org.openconext.local.oidc.ng", map.get("Issuer"));
        assertFalse(Boolean.parseBoolean((String) map.get("ForceAuthn")));
        assertTrue(((String)map.get("ID")).startsWith("ARQ"));

        Map<String, Object> scoping = (Map<String, Object>) map.get("Scoping");
        assertEquals(scoping.get("RequesterID"), "mock-sp");
    }

    @SneakyThrows
    private String inflate(byte[] b) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InflaterOutputStream iout = new InflaterOutputStream(out, new Inflater(true));
        iout.write(b);
        iout.finish();
        return out.toString(UTF_8);
    }


}