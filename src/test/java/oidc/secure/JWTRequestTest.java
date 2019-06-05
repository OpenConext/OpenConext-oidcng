package oidc.secure;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import oidc.TestUtils;
import oidc.endpoints.MapTypeReference;
import oidc.exceptions.UnsupportedJWTException;
import oidc.model.OpenIDClient;
import org.junit.Rule;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.junit.Assert.assertEquals;

public class JWTRequestTest implements TestUtils, MapTypeReference, SignedJWTTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(8089);


    @Test
    public void parseWithCertificate() throws Exception {
        OpenIDClient client = getClient();
        setCertificateFields(client, getStrippedCertificate(), null, null);
        String keyID = getCertificateKeyID(client);

        doParse(client, keyID);
    }

    @Test
    public void parseWithCertificateContainingPublicHeader() throws Exception {
        OpenIDClient client = getClient();
        setCertificateFields(client, readFile("keys/certificate.crt"), null, null);
        String keyID = getCertificateKeyIDFromCertificate(client.getSigningCertificate());

        doParse(client, keyID);
    }

    @Test
    public void parseWithRequestUrl() throws Exception {
        OpenIDClient client = getClient();
        String keyID = getCertificateKeyID(client);

        SignedJWT signedJWT = signedJWT(client.getClientId(), keyID);
        stubFor(get(urlPathMatching("/request")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(signedJWT.serialize())));

        AuthenticationRequest authenticationRequest = new AuthenticationRequest.Builder(ResponseType.getDefault(),
                new Scope("openid"), new ClientID(client.getClientId()), new URI("http://localhost:8080"))
                .requestURI(new URI("http://localhost:8089/request")).build();
        callParse(client, authenticationRequest);
    }


    @Test
    public void certificateToJWT() throws CertificateException {
        X509Certificate x509Certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream((readFile("keys/certificate.crt")).getBytes()));
        RSAKey build = new RSAKey.Builder((RSAPublicKey) x509Certificate.getPublicKey())
                .algorithm(new Algorithm("RS256"))
                .keyID("key_id")
                .build();

        assertEquals("RSA", build.toJSONObject().get("kty"));
    }

    @Test
    public void parseWithCertificateUrl() throws Exception {
        OpenIDClient client = getClient();
        setCertificateFields(client, null, "http://localhost:8089/certs", null);
        stubFor(get(urlPathMatching("/certs")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("keys/rp_public_keys.json"))));
        doParse(client, "key_id");
    }

    @Test
    public void parseWithDiscoveryUrl() throws Exception {
        OpenIDClient client = getClient();
        setCertificateFields(client, null, null, "http://localhost:8089/discovery");

        stubFor(get(urlPathMatching("/discovery")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("keys/openid_rp_configuration.json"))));
        stubFor(get(urlPathMatching("/certs")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("keys/rp_public_keys.json"))));

        doParse(client, "key_id");
    }

    @Test(expected = UnsupportedJWTException.class)
    public void invalidRP() throws Exception {
        OpenIDClient client = getClient();
        setCertificateFields(client, null, null, null);
        doParse(client, "key_id");
    }

    @Test(expected = UnsupportedJWTException.class)
    public void plainJWT() throws Exception {
        OpenIDClient client = getClient();
        signedJWT(client.getClientId(), "keyID");
        PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder().jwtID(UUID.randomUUID().toString()).build());
        AuthenticationRequest authenticationRequest = new AuthenticationRequest.Builder(ResponseType.getDefault(),
                new Scope("openid"), new ClientID(client.getClientId()), new URI("http://localhost:8080"))
                .requestObject(jwt).build();
        callParse(client, authenticationRequest);
    }

    private void doParse(OpenIDClient client, String keyID) throws Exception {
        SignedJWT signedJWT = signedJWT(client.getClientId(), keyID);
        AuthenticationRequest authenticationRequest = new AuthenticationRequest.Builder(
                ResponseType.getDefault(),
                new Scope("openid"),
                new ClientID(client.getClientId()),
                new URI("http://localhost:8080"))
                .state(new State("old"))
                .requestObject(signedJWT).build();
        callParse(client, authenticationRequest);
    }

    private void callParse(OpenIDClient client, AuthenticationRequest authenticationRequest) throws Exception {
        AuthenticationRequest parsed = JWTRequest.parse(authenticationRequest, client);
        assertEquals("openid groups", parsed.getScope().toString());
        assertEquals("123456", parsed.getNonce().getValue());
        assertEquals("new", parsed.getState().getValue());
        assertEquals("loa1 loa2 loa3", parsed.getACRValues().stream().map(ACR::getValue).collect(Collectors.joining(" ")));

        Collection<ClaimsRequest.Entry> claims = parsed.getClaims().getIDTokenClaims();
        assertEquals(1, claims.size());
        assertEquals("email", claims.iterator().next().getClaimName());
    }

    private OpenIDClient getClient() throws IOException {
        return relyingParties().stream().map(OpenIDClient::new).filter(c -> c.getClientId().equals("mock-sp")).findAny().orElseThrow(IllegalArgumentException::new);
    }

    private String getStrippedCertificate() {
        return readFile("keys/certificate.crt").replaceAll("\\Q-----BEGIN CERTIFICATE-----\\E|\\Q-----END CERTIFICATE-----\\E|\n", "");
    }

}