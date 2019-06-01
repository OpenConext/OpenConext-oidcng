package oidc.secure;

import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.proc.BadJOSEException;
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
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

public class JWTRequestTest implements TestUtils, MapTypeReference {

    @Test
    public void parse() throws Exception {
        //TODO extend AbstractIntegrationTest and set the default discovery url and use tokenGenerator to create the id_token
        Instant instant = Clock.systemDefaultZone().instant();
        OpenIDClient client = relyingParties().stream().map(OpenIDClient::new).filter(c -> c.getClientId().equals("mock-sp")).findAny().orElseThrow(IllegalArgumentException::new);

        ClaimsRequest claimsRequest = new ClaimsRequest();
        claimsRequest.addIDTokenClaim("email");

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
        String keyID = ((X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(new String("-----BEGIN CERTIFICATE-----\n" + client.getSigningCertificate() + "\n-----END CERTIFICATE-----").getBytes())))
                .getSerialNumber().toString(10);
        JWSHeader header = new JWSHeader.Builder(TokenGenerator.signingAlg).type(JOSEObjectType.JWT).keyID(keyID).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner jswsSigner = new RSASSASigner(privateKey());
        signedJWT.sign(jswsSigner);
        AuthenticationRequest authenticationRequest = new AuthenticationRequest.Builder(ResponseType.getDefault(),
                new Scope("openid"), new ClientID(client.getClientId()), new URI("http://localhost:8080"))
                .requestObject(signedJWT).build();

        Map<String, String> parameters = JWTRequest.parse(authenticationRequest, client);
        assertEquals("openid groups", parameters.get("scope"));

    }

    private RSAPrivateKey privateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKey = readFile("keys/key.pem")
                .replaceAll("\\Q-----BEGIN PRIVATE KEY-----\\E|\\Q-----END PRIVATE KEY-----\\E|\n", "");
        byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes());
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }
}