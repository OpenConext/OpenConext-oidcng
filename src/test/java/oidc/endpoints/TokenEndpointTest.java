package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import oidc.AbstractIntegrationTest;
import oidc.OidcEndpointTest;
import org.junit.Test;

import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;

@SuppressWarnings("unchecked")
public class TokenEndpointTest extends AbstractIntegrationTest implements OidcEndpointTest {

    @Test
    public void token() throws MalformedURLException, ParseException, JOSEException, BadJOSEException {
        String code = doAuthorize();
        Map<String, Object> body = doToken(code);
        String idToken =(String) body.get("id_token");
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
    public void clientCredentialsInvalidGrant() throws ParseException {
        Map<String, Object> body = doToken(null, "http@//mock-rp", "secret", GrantType.CLIENT_CREDENTIALS);

        assertEquals("Invalid grant", body.get("message"));
    }

    @Test
    public void invalidSecret() throws ParseException {
        Map<String, Object> body = doToken(null, "http@//mock-sp", "nope", GrantType.CLIENT_CREDENTIALS);

        assertEquals("Invalid user / secret", body.get("details"));
    }

}