package oidc.secure;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import oidc.TestUtils;
import oidc.endpoints.MapTypeReference;
import oidc.model.OpenIDClient;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.junit.Assert.assertEquals;

public class JWTRequestTest implements TestUtils, MapTypeReference {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(8089);


    @Test
    public void parseWithCertificate() throws Exception {
        OpenIDClient client = getClient();
        String keyID = ((X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(("-----BEGIN CERTIFICATE-----\n" + client.getSigningCertificate() + "\n-----END CERTIFICATE-----").getBytes())))
                .getSerialNumber().toString(10);

        doParse(client, keyID);
    }

    @Test
    public void certificateToJWT() throws CertificateException, JOSEException {
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

    private void doParse(OpenIDClient client, String keyID) throws Exception {
        ClaimsRequest claimsRequest = new ClaimsRequest();
        claimsRequest.addIDTokenClaim("email");

        Instant instant = Clock.systemDefaultZone().instant();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience("audience")
                .expirationTime(Date.from(instant.plus(3600, ChronoUnit.SECONDS)))
                .jwtID(UUID.randomUUID().toString())
                .issuer(client.getClientId())
                .issueTime(Date.from(instant))
                .subject(client.getClientId())
                .notBeforeTime(new Date(System.currentTimeMillis()))
                .claim("redirect_uri", "http://localhost:8080/redirect")
                .claim("scope", "openid groups")
                .claim("nonce", "123456")
                .claim("claims", claimsRequest.toString());
        JWTClaimsSet claimsSet = builder.build();
        JWSHeader header = new JWSHeader.Builder(TokenGenerator.signingAlg).type(JOSEObjectType.JWT).keyID(keyID).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner jswsSigner = new RSASSASigner(privateKey());
        signedJWT.sign(jswsSigner);
        AuthenticationRequest authenticationRequest = new AuthenticationRequest.Builder(ResponseType.getDefault(),
                new Scope("openid"), new ClientID(client.getClientId()), new URI("http://localhost:8080"))
                .requestObject(signedJWT).build();

        Map<String, String> parameters = JWTRequest.parse(authenticationRequest, client);
        assertEquals("openid groups", parameters.get("scope"));

        Collection<ClaimsRequest.Entry> claims = ClaimsRequest.parse(parameters.get("claims")).getIDTokenClaims();
        assertEquals(1, claims.size());
        assertEquals("email", claims.iterator().next().getClaimName());
    }

    private RSAPrivateKey privateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKey = readFile("keys/key.pem")
                .replaceAll("\\Q-----BEGIN PRIVATE KEY-----\\E|\\Q-----END PRIVATE KEY-----\\E|\n", "");
        byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes());
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }

    private void setCertificateFields(OpenIDClient client, String signingCertificate, String signingCertificateUrl, String discoveryUrl) {
        ReflectionTestUtils.setField(client, "signingCertificate", signingCertificate);
        ReflectionTestUtils.setField(client, "signingCertificateUrl", signingCertificateUrl);
        ReflectionTestUtils.setField(client, "discoveryUrl", discoveryUrl);    }


    private OpenIDClient getClient() throws IOException {
        return relyingParties().stream().map(OpenIDClient::new).filter(c -> c.getClientId().equals("mock-sp")).findAny().orElseThrow(IllegalArgumentException::new);
    }

}